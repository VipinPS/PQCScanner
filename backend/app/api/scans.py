from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import get_db
from app.models.models import Repo, ScanRun, Finding, SecretFinding, CBOMEntry, FindingCVE
from app.scanner.engine import CryptoScanner, clone_repo, build_cbom_from_findings, agility_to_dict
from app.scanner.file_secrets import FileSecretsScanner
from app.scanner.dependency_scanner import DependencyScanner, DependencyFinding
from app.api.auth import require_role
from app.scanner.call_graph import analyze_repo_call_graph
import json
from app.core.config import settings
from datetime import datetime
import uuid, shutil, logging

router  = APIRouter()
logger  = logging.getLogger(__name__)

# ── Reconcile findings after a scan ──────────────────────────────────────────
def reconcile_findings(scan_run_id: str, repo_id: str, new_findings: list, db: Session):
    """
    Upsert logic — never creates duplicate open findings:

    - Existing open/re_opened finding still seen → update scan_run_id (stamp to latest scan)
    - Existing open finding absent for 2+ consecutive scans → auto_resolve it
    - Existing auto_resolved finding seen again   → re-open it
    - Existing manually_resolved seen again       → re_open for review
    - Truly new finding (never seen before)       → already inserted by caller, skip here

    We require 2 consecutive misses before auto-resolving to avoid false resolutions
    caused by transient clone failures, submodule issues, or intermittent scan gaps.
    """
    new_pairs = {(f.file_path, f.algorithm) for f in new_findings}

    existing = db.query(Finding).filter(
        Finding.repo_id  == repo_id,
        Finding.scan_run_id != scan_run_id,   # from a previous scan
        Finding.archived == False,
    ).all()

    seen_existing_pairs = set()

    for old in existing:
        pair = (old.file_path, old.algorithm)

        if old.migration_status == "false_positive":
            # Never re-open a user-confirmed false positive
            seen_existing_pairs.add(pair)

        elif old.migration_status in ("open", "re_opened") and pair in new_pairs:
            # Still present — stamp to latest scan, clear any transient miss note
            old.scan_run_id     = scan_run_id
            old.resolution_note = None
            seen_existing_pairs.add(pair)

        elif old.migration_status == "open" and pair not in new_pairs:
            # Not seen this scan — require 2 consecutive misses before auto-resolving
            # to guard against transient clone failures or submodule gaps
            if old.resolution_note and old.resolution_note.startswith("Missed scan:"):
                # Second consecutive miss — now auto-resolve
                old.migration_status = "auto_resolved"
                old.resolved_at      = datetime.utcnow()
                old.resolved_by      = "scanner"
                old.resolution_note  = "Not detected in 2 consecutive scans"
            else:
                # First miss — mark but keep open
                old.resolution_note  = f"Missed scan: {scan_run_id[:8]}"

        elif old.migration_status == "auto_resolved" and pair in new_pairs:
            # Regression
            old.migration_status = "open"
            old.scan_run_id      = scan_run_id
            old.resolved_at      = None
            old.resolved_by      = None
            old.resolution_note  = "Re-introduced in latest scan"
            seen_existing_pairs.add(pair)

        elif old.migration_status == "manually_resolved" and pair in new_pairs:
            # Needs review
            old.migration_status = "re_opened"
            old.scan_run_id      = scan_run_id
            old.resolved_at      = None
            old.resolved_by      = None
            old.resolution_note  = "Re-detected after manual resolution — please review"
            seen_existing_pairs.add(pair)

    db.commit()
    return seen_existing_pairs   # caller uses this to skip re-inserting these pairs

# ── Rebuild CBOM from scratch using only latest scans ─────────────────────────
def rebuild_cbom(db: Session):
    """
    Wipe and rebuild CBOM from the most recent completed scan per repo.
    Merges both code findings AND file secret findings (SSH keys, TLS certs, etc.)
    Only counts open/re_opened findings — resolved issues are excluded.
    """
    latest_runs = (
        db.query(ScanRun.repo_id, func.max(ScanRun.started_at).label("latest"))
        .filter(ScanRun.status == "complete")
        .group_by(ScanRun.repo_id)
        .subquery()
    )

    latest_ids = (
        db.query(ScanRun.id)
        .join(latest_runs, (ScanRun.repo_id == latest_runs.c.repo_id) &
              (ScanRun.started_at == latest_runs.c.latest))
        .scalar_subquery()
    )

    # Code findings
    current_findings = (
        db.query(Finding)
        .filter(
            Finding.scan_run_id.in_(latest_ids),
            Finding.archived         == False,
            Finding.migration_status.in_(["open", "re_opened"]),
        )
        .all()
    )

    # Secret findings (SSH keys, TLS certs, PKCS12, GPG, SSH config)
    current_secrets = (
        db.query(SecretFinding)
        .filter(
            SecretFinding.scan_run_id.in_(latest_ids),
            SecretFinding.archived         == False,
            SecretFinding.migration_status.in_(["open", "re_opened"]),
        )
        .all()
    )

    # Full rebuild
    db.query(CBOMEntry).delete()

    cbom = {}

    def _init_entry(algorithm, algo_type, quantum_status, nist_replacement):
        return {
            "algorithm":        algorithm,
            "algo_type":        algo_type,
            "quantum_status":   quantum_status,
            "nist_replacement": nist_replacement,
            "priority":         _priority(quantum_status),
            "risk_score":       _risk_score(quantum_status),
            "total_usages":     0,
            "code_usages":      0,
            "secret_usages":    0,
            "artifact_usages":  0,
            "unreachable_count":0,
            "min_call_depth":   None,
            "affected_repos":   set(),
        }

    # Pass 1 — code + dependency findings
    for f in current_findings:
        if f.algorithm not in cbom:
            cbom[f.algorithm] = _init_entry(
                f.algorithm, f.algo_type, f.quantum_status, f.nist_replacement)
        e = cbom[f.algorithm]
        e["total_usages"] += 1
        e["affected_repos"].add(f.repo_id)

        if f.source_type == "artifact":
            e["artifact_usages"] += 1
        else:
            e["code_usages"] += 1

        # Call-graph enrichment (6.2)
        if f.reachable is False:
            e["unreachable_count"] += 1
        if f.call_depth is not None:
            e["min_call_depth"] = (min(e["min_call_depth"], f.call_depth)
                                   if e["min_call_depth"] is not None else f.call_depth)

    # Pass 2 — secret findings
    for sf in current_secrets:
        algo = _normalise_secret_algo(sf.algorithm, sf.quantum_status, sf.nist_replacement)
        if algo not in cbom:
            cbom[algo] = _init_entry(
                algo, _secret_type(sf.finding_type),
                sf.quantum_status or "VULNERABLE", sf.nist_replacement)
        e = cbom[algo]
        e["total_usages"]  += 1
        e["secret_usages"] += 1
        e["affected_repos"].add(sf.repo_id)

    # Also pull in artifact findings not linked to a scan_run (standalone artifact scans)
    artifact_findings = (
        db.query(Finding)
        .filter(
            Finding.source_type      == "artifact",
            Finding.archived         == False,
            Finding.migration_status.in_(["open", "re_opened"]),
            Finding.scan_run_id.notin_(latest_ids),  # avoid double-counting
        )
        .all()
    )
    for f in artifact_findings:
        if f.algorithm not in cbom:
            cbom[f.algorithm] = _init_entry(
                f.algorithm, f.algo_type, f.quantum_status, f.nist_replacement)
        e = cbom[f.algorithm]
        e["total_usages"]    += 1
        e["artifact_usages"] += 1
        e["affected_repos"].add(f.repo_id)

    for entry in cbom.values():
        entry["affected_repos"] = len(entry["affected_repos"])
        db.add(CBOMEntry(id=str(uuid.uuid4()), **entry))

    db.commit()


def _normalise_secret_algo(algorithm: str, quantum_status: str, nist_replacement: str) -> str:
    """Map secret finding algorithm names to CBOM-friendly names for grouping."""
    a = algorithm or ""
    # RSA-2048, RSA-4096, etc. — keep as-is
    if a.startswith("RSA-"):
        return a
    # ECDSA-secp256r1 → ECDSA
    if a.startswith("ECDSA-"):
        return "ECDSA"
    # DSA variants
    if a.startswith("DSA-"):
        return "DSA"
    # Ed25519, Ed448 — keep as-is
    return a


def _secret_type(finding_type: str) -> str:
    mapping = {
        "SSH_PRIVATE_KEY": "Asymmetric",
        "SSH_PUBLIC_KEY":  "Asymmetric",
        "AUTHORIZED_KEY":  "Asymmetric",
        "TLS_CERT":        "Certificate",
        "PKCS12":          "Certificate",
        "PKCS12_CHAIN":    "Certificate",
        "GPG_KEY":         "Asymmetric",
        "SSH_CONFIG":      "Protocol",
    }
    return mapping.get(finding_type, "Asymmetric")

def _priority(qs: str) -> int:
    return {"BROKEN": 1, "VULNERABLE": 2, "WEAK": 3, "MONITOR": 4, "SAFE": 5}.get(qs, 3)

def _risk_score(qs: str) -> float:
    return {"BROKEN": 10.0, "VULNERABLE": 8.0, "WEAK": 5.0, "MONITOR": 3.0, "SAFE": 1.0}.get(qs, 3.0)

# ── Main scan job ─────────────────────────────────────────────────────────────
def run_scan_job(scan_run_id: str, repo_id: str, db: Session):
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    repo     = db.query(Repo).filter(Repo.id == repo_id).first()
    if not scan_run or not repo:
        return

    scan_run.status = "running"
    db.commit()
    tmp_path = None

    try:
        # Clone or use local path
        if repo.url.startswith("http"):
            if repo.provider == "github-enterprise":
                token = settings.GITHUB_ENTERPRISE_TOKEN or settings.GITHUB_TOKEN
            elif repo.provider == "gitlab" or "gitlab" in repo.url:
                token = settings.GITLAB_TOKEN
            elif repo.provider == "bitbucket" or "bitbucket" in repo.url:
                token = settings.BITBUCKET_TOKEN
            elif "github.com" in repo.url:
                token = settings.GITHUB_TOKEN
            elif "github" in repo.url:
                # GHE detected via URL when provider field wasn't set explicitly
                token = settings.GITHUB_ENTERPRISE_TOKEN or settings.GITHUB_TOKEN
            else:
                token = settings.GITHUB_TOKEN
            tmp_path = clone_repo(repo.url, token=token, branch=repo.branch)
        else:
            tmp_path = repo.url

        # Scan source code
        scanner = CryptoScanner()
        result  = scanner.scan_directory(tmp_path)

        # Scan SSH keys, TLS certs, PKCS12, GPG, SSH config
        secrets_scanner = FileSecretsScanner()
        secret_findings = secrets_scanner.scan_directory(tmp_path)

        # Scan dependency manifests (requirements.txt, package.json, go.mod, etc.)
        dep_scanner = DependencyScanner()
        dep_findings = dep_scanner.scan_directory(tmp_path)

        # Reconcile source code findings FIRST
        already_tracked = reconcile_findings(scan_run_id, repo_id, result.findings, db)

        # Persist new code findings — only those not already tracked by reconcile
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        max_risk   = "LOW"

        for f in result.findings:
            pair = (f.file_path, f.algorithm)
            if pair in already_tracked:
                # Already exists — reconcile stamped it to this scan_run_id, skip insert
                if risk_order.get(f.risk_level, 99) < risk_order.get(max_risk, 99):
                    max_risk = f.risk_level
                continue
            db.add(Finding(
                id                 = str(uuid.uuid4()),
                scan_run_id        = scan_run_id,
                repo_id            = repo_id,
                file_path          = f.file_path,
                line_number        = f.line_number,
                algorithm          = f.algorithm,
                algo_type          = f.algo_type,
                context            = f.context,
                context_start_line = f.context_start_line,
                risk_level         = f.risk_level,
                quantum_status     = f.quantum_status,
                quantum_safe       = f.quantum_safe,
                nist_replacement   = f.nist_replacement,
                migration_status   = "open",
                in_test_path       = f.in_test_path,
            ))
            if risk_order.get(f.risk_level, 99) < risk_order.get(max_risk, 99):
                max_risk = f.risk_level

        # Persist dependency findings — full replace on each scan
        old_dep_ids = [row[0] for row in db.query(Finding.id).filter(
            Finding.repo_id == repo_id,
            Finding.source_type == "dependency",
        ).all()]
        if old_dep_ids:
            db.query(FindingCVE).filter(FindingCVE.finding_id.in_(old_dep_ids)).delete(synchronize_session=False)
        db.query(Finding).filter(
            Finding.repo_id == repo_id,
            Finding.source_type == "dependency",
        ).delete(synchronize_session=False)
        for df in dep_findings:
            finding_id = str(uuid.uuid4())
            db.add(Finding(
                id                 = finding_id,
                scan_run_id        = scan_run_id,
                repo_id            = repo_id,
                file_path          = df.file_path,
                line_number        = df.line_number,
                algorithm          = df.algorithm,
                algo_type          = df.algo_type,
                context            = df.context,
                risk_level         = df.risk_level,
                quantum_status     = df.quantum_status,
                quantum_safe       = df.quantum_safe,
                nist_replacement   = df.nist_replacement,
                migration_status   = "open",
                source_type        = "dependency",
                dependency_name    = df.dependency_name,
                dependency_version = df.dependency_version,
                ecosystem          = df.ecosystem,
            ))
            for cve in df.cves:
                db.add(FindingCVE(
                    finding_id    = finding_id,
                    cve_id        = cve["cve_id"],
                    summary       = cve.get("summary"),
                    cvss_score    = cve.get("cvss_score"),
                    cvss_severity = cve.get("cvss_severity"),
                    source        = cve.get("source", "osv"),
                ))
            if risk_order.get(df.risk_level, 99) < risk_order.get(max_risk, 99):
                max_risk = df.risk_level

        # Persist secret findings (keys / certs) — full replace on each scan
        db.query(SecretFinding).filter(SecretFinding.repo_id == repo_id).delete()
        for sf in secret_findings:
            if sf.error:
                continue
            db.add(SecretFinding(
                id               = str(uuid.uuid4()),
                scan_run_id      = scan_run_id,
                repo_id          = repo_id,
                file_path        = sf.file_path,
                finding_type     = sf.finding_type,
                algorithm        = sf.algorithm,
                key_size         = sf.key_size,
                curve            = sf.curve,
                quantum_status   = sf.quantum_status,
                risk_level       = sf.risk_level,
                nist_replacement = sf.nist_replacement,
                subject          = sf.subject,
                issuer           = sf.issuer,
                not_before       = sf.not_before,
                not_after        = sf.not_after,
                expiry_status    = sf.expiry_status,
                serial           = sf.serial,
                config_key       = sf.config_key,
                config_value     = sf.config_value,
                context          = sf.context,
                migration_status = "open",
            ))
            if risk_order.get(sf.risk_level, 99) < risk_order.get(max_risk, 99):
                max_risk = sf.risk_level

        db.flush()

        # ── Collect source-code findings from this scan run to annotate ────────
        sc_findings = db.query(Finding).filter(
            Finding.scan_run_id == scan_run_id,
            Finding.source_type == "source_code",
            Finding.archived    == False,
        ).all()

        # ── Path-based false-positive heuristic ─────────────────────────────────
        # Findings in test/fixture/example/vendor paths carry little production
        # risk — suggest them as likely false positives ahead of AI validation.
        TEST_PATH_FP_EXPLANATION = (
            "This file's path matches common test/fixture/example/vendor "
            "patterns, so this crypto usage is unlikely to represent "
            "production risk. Review before confirming."
        )
        for fobj in sc_findings:
            if fobj.in_test_path and not fobj.ai_validated:
                fobj.ai_label       = "false_positive"
                fobj.ai_confidence  = 0.65
                fobj.ai_explanation = TEST_PATH_FP_EXPLANATION
        db.flush()

        # ── Phase 5: Call graph analysis ──────────────────────────────────────
        try:
            if sc_findings and tmp_path:
                finding_tuples = [
                    (f.id, f.file_path, f.line_number, f.source_type)
                    for f in sc_findings
                ]
                cg_results = analyze_repo_call_graph(tmp_path, finding_tuples)
                for finding_id, (reachable, depth, chain) in cg_results.items():
                    fobj = next((f for f in sc_findings if f.id == finding_id), None)
                    if not fobj:
                        continue
                    fobj.reachable  = reachable
                    fobj.call_depth = depth
                    fobj.call_chain = json.dumps(chain) if chain else None
                    # 5.5: Suggest false positive for findings unreachable from any entry point
                    if not reachable and not fobj.ai_validated:
                        if fobj.ai_label == "false_positive" and fobj.in_test_path:
                            # Already flagged via path heuristic — both signals agree
                            fobj.ai_confidence  = 0.85
                            fobj.ai_explanation = (
                                TEST_PATH_FP_EXPLANATION + " In addition, static call "
                                "graph analysis found no path from any known entry "
                                "point to this function — the crypto usage is very "
                                "likely test-only or dead code."
                            )
                        else:
                            fobj.ai_label       = "false_positive"
                            fobj.ai_confidence  = 0.75
                            fobj.ai_explanation = (
                                "Static call graph analysis found no path from any known "
                                "entry point to this function. The crypto usage may be dead "
                                "code or test-only. Review before confirming."
                            )
                db.flush()
        except Exception as cg_err:
            logger.warning("Call graph analysis failed (non-fatal): %s", cg_err)

        # Update repo
        repo.risk_level      = max_risk
        repo.last_scanned_at = datetime.utcnow()

        # Persist agility scoring
        if result.agility:
            ad = agility_to_dict(result.agility)
            repo.agility_level   = ad["agility_level"]
            repo.agility_label   = ad["agility_label"]
            repo.agility_score   = ad["agility_score"]
            repo.has_hybrid      = ad["has_hybrid"]
            repo.agility_signals = json.dumps(ad["agility_signals"])

        # Update scan run stats
        scan_run.total_files    = result.total_files
        scan_run.scanned_files  = result.scanned_files
        scan_run.total_findings = len(result.findings) + len(dep_findings)
        scan_run.status         = "complete"
        scan_run.completed_at   = datetime.utcnow()

        db.commit()

        # Rebuild CBOM from scratch after commit
        rebuild_cbom(db)

    except Exception as e:
        logger.exception("Scan failed")
        scan_run.status        = "failed"
        scan_run.error_message = str(e)
        scan_run.completed_at  = datetime.utcnow()
        db.commit()
    finally:
        if tmp_path and tmp_path.startswith("/tmp"):
            shutil.rmtree(tmp_path, ignore_errors=True)

# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/{repo_id}/trigger", status_code=202)
def trigger_scan(repo_id: str, bg: BackgroundTasks, db: Session = Depends(get_db),
                 _session = Depends(require_role("admin", "dev"))):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")
    scan_run = ScanRun(id=str(uuid.uuid4()), repo_id=repo_id)
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    bg.add_task(run_scan_job, scan_run.id, repo_id, db)
    return {"scan_run_id": scan_run.id, "status": "queued"}

@router.post("/scan-all", status_code=202)
def scan_all(bg: BackgroundTasks, project_id: str = None,
             db: Session = Depends(get_db),
             _session=Depends(require_role("admin"))):
    """
    Queue a full scan for every repo (optionally filtered by project).
    Also re-queues any artifact scans that previously failed.
    Tries Celery first; falls back to FastAPI BackgroundTasks if the
    broker is unavailable (dev / single-container setups).
    """
    from app.models.models import Artifact

    q = db.query(Repo)
    if project_id:
        q = q.filter(Repo.project_id == project_id)
    repos = q.all()

    if not repos:
        return {"status": "nothing_to_scan", "scan_count": 0}

    # Create ScanRun records up-front so the client can track progress
    scan_runs: list[tuple[str, str]] = []   # (scan_run_id, repo_id)
    for repo in repos:
        sr = ScanRun(id=str(uuid.uuid4()), repo_id=repo.id, scan_type="code")
        db.add(sr)
        scan_runs.append((sr.id, repo.id))
    db.commit()

    # Artifacts to re-scan (failed or stuck pending)
    artifact_runs: list[tuple] = []
    for repo in repos:
        arts = db.query(Artifact).filter(
            Artifact.repo_id   == repo.id,
            Artifact.scan_status.in_(["failed", "pending"]),
            Artifact.file_path != None,
        ).all()
        for a in arts:
            artifact_runs.append((a.id, repo.id, a.file_path,
                                   a.artifact_type, a.name))

    # ── Dispatch — Celery preferred, BackgroundTasks fallback ────────────────
    def _bg_scan(run_id, rid):
        """BackgroundTask wrapper that creates its own DB session."""
        from app.db.database import SessionLocal as _SL
        _db = _SL()
        try:
            run_scan_job(run_id, rid, _db)
        finally:
            _db.close()

    def _bg_artifact(art_id, rid, fpath, atype, aname):
        from app.api.artifacts import _run_artifact_scan
        _run_artifact_scan(art_id, rid, fpath, atype, aname)

    use_celery = False
    try:
        from app.tasks.scan_tasks import scan_repo_task, scan_artifact_task
        from celery import group as celery_group

        jobs = [scan_repo_task.s(run_id, repo_id) for run_id, repo_id in scan_runs]
        jobs += [scan_artifact_task.s(aid, rid, fp, at, an)
                 for aid, rid, fp, at, an in artifact_runs]
        result = celery_group(jobs).apply_async()
        use_celery = True
        group_id   = str(result.id) if hasattr(result, "id") else None
    except Exception as cel_err:
        logger.info("Celery unavailable (%s) — using BackgroundTasks", cel_err)
        for run_id, repo_id in scan_runs:
            bg.add_task(_bg_scan, run_id, repo_id)
        for aid, rid, fp, at, an in artifact_runs:
            bg.add_task(_bg_artifact, aid, rid, fp, at, an)
        group_id = None

    return {
        "status":          "queued",
        "scan_count":      len(scan_runs),
        "artifact_count":  len(artifact_runs),
        "engine":          "celery" if use_celery else "background",
        "group_id":        group_id,
    }

@router.get("/{repo_id}/runs")
def list_runs(repo_id: str, db: Session = Depends(get_db)):
    return (db.query(ScanRun).filter(ScanRun.repo_id == repo_id)
            .order_by(ScanRun.started_at.desc()).all())

@router.get("/runs/{scan_run_id}")
def get_run(scan_run_id: str, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not run:
        raise HTTPException(404, "Not found")
    return run

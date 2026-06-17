import csv
import io
import uuid
from datetime import datetime, timezone
from collections import defaultdict
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import CBOMEntry, Finding, SecretFinding, Repo, Project

router = APIRouter()


def _build_url(repo_url: str, branch: str, file_path: str, line_number=None) -> str:
    """Return a GitHub/GitLab blob URL for a specific file and optional line."""
    base = repo_url.rstrip("/")
    # Normalise: strip trailing .git
    if base.endswith(".git"):
        base = base[:-4]
    path = f"{base}/blob/{branch or 'main'}/{file_path.lstrip('/')}"
    if line_number:
        path += f"#L{line_number}"
    return path

@router.get("/")
def get_cbom(project_id: str = None, db: Session = Depends(get_db)):
    q = db.query(CBOMEntry).order_by(CBOMEntry.priority)
    if project_id:
        repo_ids = [r.id for r in db.query(Repo.id).filter(Repo.project_id == project_id).all()]
        # Algorithms from code/dependency findings
        code_algos = {row[0] for row in
                      db.query(Finding.algorithm).filter(
                          Finding.repo_id.in_(repo_ids),
                          Finding.archived == False,
                          Finding.migration_status != "false_positive",
                      ).distinct().all()}
        # Algorithms from file-secret findings (SSH keys, TLS certs, etc.)
        secret_algos = {row[0] for row in
                        db.query(SecretFinding.algorithm).filter(
                            SecretFinding.repo_id.in_(repo_ids),
                            SecretFinding.archived == False,
                            SecretFinding.migration_status != "false_positive",
                        ).distinct().all()}
        algos = list(code_algos | secret_algos)
        q = q.filter(CBOMEntry.algorithm.in_(algos))
    return q.all()

# Maps quantum_status to NIST PQC security level (best-effort)
_NIST_QSL = {
    "SAFE":       3,   # already PQC-safe
    "MONITOR":    2,
    "WEAK":       1,
    "VULNERABLE": 0,
    "BROKEN":     0,
}

@router.get("/export/cyclonedx")
def export_cyclonedx(project_id: str = None, db: Session = Depends(get_db)):
    entries = db.query(CBOMEntry).order_by(CBOMEntry.priority).all()

    repo_filter = []
    if project_id:
        repo_filter = [r.id for r in db.query(Repo.id).filter(Repo.project_id == project_id).all()]

    # Collect file occurrences per algorithm from code findings (non-archived, non-false-positive)
    code_q = (
        db.query(
            Finding.algorithm, Finding.file_path, Finding.line_number,
            Repo.url, Repo.branch,
        )
        .join(Repo, Finding.repo_id == Repo.id)
        .filter(Finding.archived == False, Finding.migration_status != "false_positive")
    )
    if repo_filter:
        code_q = code_q.filter(Finding.repo_id.in_(repo_filter))
    code_findings = code_q.all()

    # Collect file occurrences from secret findings (non-archived, non-false-positive)
    secret_q = (
        db.query(SecretFinding.algorithm, SecretFinding.file_path, Repo.url, Repo.branch)
        .join(Repo, SecretFinding.repo_id == Repo.id)
        .filter(SecretFinding.archived == False, SecretFinding.migration_status != "false_positive")
    )
    if repo_filter:
        secret_q = secret_q.filter(SecretFinding.repo_id.in_(repo_filter))
    secret_findings = secret_q.all()

    # Build algorithm → [full URL location strings] map
    occurrences: dict[str, list[str]] = defaultdict(list)
    for algo, path, line, repo_url, branch in code_findings:
        loc = _build_url(repo_url, branch, path, line)
        occurrences[algo].append(loc)
    for algo, path, repo_url, branch in secret_findings:
        loc = _build_url(repo_url, branch, path)
        if loc not in occurrences[algo]:
            occurrences[algo].append(loc)

    components = []
    for e in entries:
        locs = occurrences.get(e.algorithm, [])
        component = {
            "type": "cryptographic-asset",
            "bom-ref": str(uuid.uuid4()),
            "name": e.algorithm,
            "cryptoProperties": {
                "assetType": e.algo_type,
                "algorithmProperties": {
                    "nistQuantumSecurityLevel": _NIST_QSL.get(e.quantum_status, 0),
                },
            },
            "x-pqc-status":       e.quantum_status,
            "x-nist-replacement": e.nist_replacement,
            "x-total-usages":     e.total_usages,
            "x-affected-repos":   e.affected_repos,
        }
        if locs:
            component["evidence"] = {
                "occurrences": [{"location": loc} for loc in locs]
            }
        components.append(component)

    return {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.5",
        "version":     1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": "PQCScanner"},
        },
        "components": components,
    }


@router.get("/export/csv")
def export_csv(project_id: str = None, db: Session = Depends(get_db)):
    """Export CBOM as CSV — one row per finding location (file + line)."""
    entries = db.query(CBOMEntry).order_by(CBOMEntry.priority).all()

    repo_filter = []
    project_name = None
    if project_id:
        repo_filter = [r.id for r in db.query(Repo.id).filter(Repo.project_id == project_id).all()]
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj:
            project_name = proj.name.lower().replace(" ", "-")

    code_q = (
        db.query(
            Finding.algorithm, Finding.file_path, Finding.line_number,
            Finding.algo_type, Finding.risk_level, Finding.quantum_status,
            Finding.nist_replacement, Finding.migration_status,
            Repo.url, Repo.branch, Repo.name,
        )
        .join(Repo, Finding.repo_id == Repo.id)
        .filter(Finding.archived == False, Finding.migration_status != "false_positive")
    )
    if repo_filter:
        code_q = code_q.filter(Finding.repo_id.in_(repo_filter))
    code_findings = code_q.all()

    secret_q = (
        db.query(
            SecretFinding.algorithm, SecretFinding.file_path,
            SecretFinding.finding_type, SecretFinding.risk_level,
            SecretFinding.quantum_status, SecretFinding.nist_replacement,
            Repo.url, Repo.branch, Repo.name,
        )
        .join(Repo, SecretFinding.repo_id == Repo.id)
        .filter(SecretFinding.archived == False, SecretFinding.migration_status != "false_positive")
    )
    if repo_filter:
        secret_q = secret_q.filter(SecretFinding.repo_id.in_(repo_filter))
    secret_findings = secret_q.all()

    # Build lookup: algorithm → CBOMEntry metadata
    cbom_meta = {e.algorithm: e for e in entries}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "algorithm", "type", "quantum_status", "risk_level",
        "nist_replacement", "repo", "file_path", "line_number",
        "source_url",        # full blob URL with line anchor
        "source",            # code | secret
        "migration_status",
        "total_usages", "affected_repos",
    ])

    for row in code_findings:
        algo, path, line, atype, risk, qstatus, nist, mstatus, rurl, branch, rname = row
        meta = cbom_meta.get(algo)
        source_url = _build_url(rurl, branch, path, line)
        writer.writerow([
            algo, atype, qstatus, risk, nist or "",
            rname, path, line or "",
            source_url,
            "code", mstatus or "open",
            meta.total_usages if meta else "",
            meta.affected_repos if meta else "",
        ])

    for row in secret_findings:
        algo, path, ftype, risk, qstatus, nist, rurl, branch, rname = row
        meta = cbom_meta.get(algo)
        source_url = _build_url(rurl, branch, path)
        writer.writerow([
            algo, ftype, qstatus, risk, nist or "",
            rname, path, "",
            source_url,
            "secret", "open",
            meta.total_usages if meta else "",
            meta.affected_repos if meta else "",
        ])

    output.seek(0)
    suffix = f"-{project_name}" if project_name else ""
    filename = f"cbom{suffix}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

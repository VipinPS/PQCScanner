from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import func
from app.db.database import get_db
from app.models.models import Finding, Repo, FindingCVE
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter()

# ── Schemas ───────────────────────────────────────────────────────────────────
class StatusUpdate(BaseModel):
    status:          str            # open | manually_resolved | re_opened
    resolved_by:     Optional[str] = "user"
    resolution_note: Optional[str] = None
    migrated_to:     Optional[str] = None   # e.g. "ML-KEM-768 (FIPS 203)" 

class ArchiveRequest(BaseModel):
    archived_by: Optional[str] = "user"

# ── Summary ───────────────────────────────────────────────────────────────────
@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    base = db.query(Finding).filter(Finding.archived == False)
    risk_counts   = base.with_entities(Finding.risk_level, func.count(Finding.id)).group_by(Finding.risk_level).all()
    algo_counts   = (base.with_entities(Finding.algorithm, func.count(Finding.id))
                     .group_by(Finding.algorithm).order_by(func.count(Finding.id).desc()).limit(10).all())
    qs_counts     = base.with_entities(Finding.quantum_status, func.count(Finding.id)).group_by(Finding.quantum_status).all()
    status_counts = (base.with_entities(Finding.migration_status, func.count(Finding.id))
                     .group_by(Finding.migration_status).all())
    source_counts = (base.with_entities(Finding.source_type, func.count(Finding.id))
                     .group_by(Finding.source_type).all())

    return {
        "by_risk":            dict(risk_counts),
        "by_quantum_status":  dict(qs_counts),
        "top_algorithms":     dict(algo_counts),
        "by_status":          dict(status_counts),
        "by_source":          dict(source_counts),   # source_code vs dependency counts
        "total":              base.count(),
        "archived_count":     db.query(Finding).filter(Finding.archived == True).count(),
    }

# ── List findings ─────────────────────────────────────────────────────────────
@router.get("/")
def list_findings(
    repo_id:          str  = Query(None),
    project_id:       str  = Query(None),
    risk_level:       str  = Query(None),
    quantum_status:   str  = Query(None),
    algorithm:        str  = Query(None),
    migration_status: str  = Query(None),
    source_type:      str  = Query(None),
    cve_id:           str  = Query(None),
    search:           str  = Query(None),
    include_archived: bool = Query(False),
    skip:             int  = 0,
    limit:            int  = 200,
    db: Session = Depends(get_db)
):
    q = db.query(Finding).options(selectinload(Finding.cves))
    if not include_archived:
        q = q.filter(Finding.archived == False)
    if project_id:
        repo_ids = [r.id for r in db.query(Repo.id).filter(Repo.project_id == project_id).all()]
        q = q.filter(Finding.repo_id.in_(repo_ids))
    if repo_id:          q = q.filter(Finding.repo_id          == repo_id)
    if risk_level:       q = q.filter(Finding.risk_level       == risk_level)
    if quantum_status:   q = q.filter(Finding.quantum_status   == quantum_status)
    if algorithm:        q = q.filter(Finding.algorithm.ilike(f"%{algorithm}%"))
    if migration_status: q = q.filter(Finding.migration_status == migration_status)
    if source_type:      q = q.filter(Finding.source_type      == source_type)
    if cve_id:
        q = q.join(FindingCVE, FindingCVE.finding_id == Finding.id).filter(FindingCVE.cve_id.ilike(f"%{cve_id}%"))
    if search:
        pattern = f"%{search}%"
        q = q.filter(
            Finding.file_path.ilike(pattern) | Finding.algorithm.ilike(pattern)
        )
    return q.order_by(Finding.risk_level, Finding.created_at.desc()).offset(skip).limit(limit).all()

# ── Update single finding status ──────────────────────────────────────────────
@router.patch("/{finding_id}/status")
def update_status(finding_id: str, payload: StatusUpdate, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    allowed = {"open", "manually_resolved", "re_opened", "false_positive"}
    if payload.status not in allowed:
        raise HTTPException(400, f"Status must be one of: {allowed}")

    finding.migration_status = payload.status
    finding.resolved_by      = payload.resolved_by
    finding.resolution_note  = payload.resolution_note
    finding.migrated_to      = payload.migrated_to
    finding.resolved_at      = (
        datetime.utcnow()
        if "resolved" in payload.status or payload.status == "false_positive"
        else None
    )
    db.commit()
    db.refresh(finding)
    return finding

# ── Soft-delete (archive) a single finding ────────────────────────────────────
@router.patch("/{finding_id}/archive")
def archive_finding(finding_id: str, payload: ArchiveRequest, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.archived    = True
    finding.archived_at = datetime.utcnow()
    finding.archived_by = payload.archived_by
    db.commit()
    return {"archived": True, "id": finding_id}

# ── Restore archived finding ──────────────────────────────────────────────────
@router.patch("/{finding_id}/restore")
def restore_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.archived    = False
    finding.archived_at = None
    finding.archived_by = None
    db.commit()
    return {"restored": True, "id": finding_id}

# ── Bulk archive resolved findings (soft delete) ──────────────────────────────
@router.post("/archive-resolved")
def archive_resolved(payload: ArchiveRequest, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(
        Finding.migration_status.in_(["auto_resolved", "manually_resolved"]),
        Finding.archived == False,
    ).all()

    count = 0
    for f in findings:
        f.archived    = True
        f.archived_at = datetime.utcnow()
        f.archived_by = payload.archived_by
        count += 1

    db.commit()
    return {"archived": count}

# ── List archived findings (audit trail) ─────────────────────────────────────
@router.get("/archived")
def list_archived(
    repo_id:    str = Query(None),
    search:     str = Query(None),
    skip:       int = 0,
    limit:      int = 200,
    db: Session = Depends(get_db)
):
    q = db.query(Finding).filter(Finding.archived == True)
    if repo_id: q = q.filter(Finding.repo_id == repo_id)
    if search:
        pattern = f"%{search}%"
        q = q.filter(
            Finding.file_path.ilike(pattern) | Finding.algorithm.ilike(pattern)
        )
    return q.order_by(Finding.archived_at.desc()).offset(skip).limit(limit).all()

# ── Migration tracking stats ──────────────────────────────────────────────────
@router.get("/migration-stats")
def migration_stats(
    repo_id: str = Query(None),
    db: Session = Depends(get_db)
):
    """
    Per-algorithm migration progress: how many open vs resolved, and what
    algorithms have been migrated TO.
    """
    from app.models.models import Repo
    base = db.query(Finding).filter(Finding.archived == False)
    if repo_id:
        base = base.filter(Finding.repo_id == repo_id)

    all_findings = base.all()

    # Group by algorithm
    algo_map = {}
    for f in all_findings:
        a = f.algorithm
        if a not in algo_map:
            algo_map[a] = {
                "algorithm":       a,
                "risk_level":      f.risk_level,
                "quantum_status":  f.quantum_status,
                "nist_replacement":f.nist_replacement,
                "open":            0,
                "auto_resolved":   0,
                "manually_resolved": 0,
                "re_opened":       0,
                "migrated_to":     {},   # replacement → count
                "total":           0,
            }
        algo_map[a]["total"] += 1
        status = f.migration_status or "open"
        algo_map[a][status] = algo_map[a].get(status, 0) + 1
        if f.migrated_to:
            mt = algo_map[a]["migrated_to"]
            mt[f.migrated_to] = mt.get(f.migrated_to, 0) + 1

    # Compute per-algo progress %
    stats = []
    for a, d in algo_map.items():
        resolved = d["auto_resolved"] + d["manually_resolved"]
        pct = round(resolved / d["total"] * 100) if d["total"] else 0
        stats.append({**d, "resolved": resolved, "progress_pct": pct})

    # Sort by risk severity then progress
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    stats.sort(key=lambda x: (order.get(x["risk_level"], 9), -x["open"]))

    # Hybrid mode repos
    hybrid_repos = []
    if not repo_id:
        repos = db.query(Repo).filter(Repo.has_hybrid == True).all()
        hybrid_repos = [
            {
                "id":            r.id,
                "name":          r.name,
                "agility_level": r.agility_level,
                "agility_label": r.agility_label,
                "agility_signals": r.agility_signals,
            }
            for r in repos
        ]

    return {
        "algorithm_stats": stats,
        "hybrid_repos":    hybrid_repos,
        "total_findings":  len(all_findings),
    }


# ── CVE Overlay ───────────────────────────────────────────────────────────────

@router.get("/cve-stats")
def cve_stats(db: Session = Depends(get_db)):
    """Aggregate CVE exposure across all (non-archived) dependency findings."""
    base = (
        db.query(FindingCVE)
        .join(Finding, Finding.id == FindingCVE.finding_id)
        .filter(Finding.archived == False)
    )
    total_cve_records = base.count()
    distinct_cves     = base.with_entities(FindingCVE.cve_id).distinct().count()

    top = (
        base.with_entities(
            FindingCVE.cve_id,
            FindingCVE.cvss_severity,
            func.count(func.distinct(Finding.repo_id)),
        )
        .group_by(FindingCVE.cve_id, FindingCVE.cvss_severity)
        .order_by(func.count(func.distinct(Finding.repo_id)).desc())
        .limit(5)
        .all()
    )

    dep_total = db.query(Finding).filter(
        Finding.source_type == "dependency",
        Finding.archived    == False,
    ).count()
    dep_with_cve = (
        db.query(Finding.id)
        .join(FindingCVE, FindingCVE.finding_id == Finding.id)
        .filter(Finding.source_type == "dependency", Finding.archived == False)
        .distinct()
        .count()
    )

    return {
        "total_cve_records":           total_cve_records,
        "distinct_cves":                distinct_cves,
        "top_cves": [
            {"cve_id": cve_id, "cvss_severity": severity, "affected_repos": count}
            for cve_id, severity, count in top
        ],
        "dependency_findings_total":   dep_total,
        "dependency_findings_with_cve": dep_with_cve,
        "coverage_pct": round(dep_with_cve / dep_total * 100) if dep_total else 0,
    }


@router.get("/{finding_id}/cves")
def get_finding_cves(finding_id: str, db: Session = Depends(get_db)):
    """List the CVE/CVSS records associated with a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return [
        {
            "id":            c.id,
            "cve_id":        c.cve_id,
            "summary":       c.summary,
            "cvss_score":    c.cvss_score,
            "cvss_severity": c.cvss_severity,
            "source":        c.source,
            "fetched_at":    c.fetched_at,
        }
        for c in finding.cves
    ]


@router.post("/enrich-cves")
def enrich_cves(
    repo_id: str = Query(None),
    db: Session = Depends(get_db),
):
    """
    Re-query OSV.dev for existing dependency findings that have no CVE
    records yet, and persist any crypto-relevant CVEs found.
    """
    from app.scanner.dependency_scanner import _query_osv, _cvss_score, _cvss_to_risk, ParsedPackage

    q = db.query(Finding).options(selectinload(Finding.cves)).filter(
        Finding.source_type == "dependency",
        Finding.archived    == False,
    )
    if repo_id:
        q = q.filter(Finding.repo_id == repo_id)

    findings = [f for f in q.all() if not f.cves and f.dependency_name and f.ecosystem]
    if not findings:
        return {"checked": 0, "packages_queried": 0, "new_cves": 0}

    packages, seen = [], set()
    for f in findings:
        key = (f.ecosystem, f.dependency_name.lower())
        if key in seen:
            continue
        seen.add(key)
        packages.append(ParsedPackage(
            name=f.dependency_name.lower(), version=f.dependency_version or "",
            ecosystem=f.ecosystem, manifest=f.file_path,
        ))

    osv_results = _query_osv(packages)

    new_cves = 0
    for f in findings:
        key = (f.ecosystem, f.dependency_name.lower())
        for vuln in osv_results.get(key, []):
            db.add(FindingCVE(
                finding_id    = f.id,
                cve_id        = vuln.get("id", "Unknown"),
                summary       = vuln.get("summary", "Crypto vulnerability detected"),
                cvss_score    = _cvss_score(vuln),
                cvss_severity = _cvss_to_risk(vuln),
                source        = "osv",
            ))
            new_cves += 1

    db.commit()
    return {"checked": len(findings), "packages_queried": len(packages), "new_cves": new_cves}


# ── AI Validation ─────────────────────────────────────────────────────────────

@router.post("/{finding_id}/validate")
def trigger_ai_validation(finding_id: str, db: Session = Depends(get_db)):
    """Queue an async Celery task to validate this finding with Granite AI."""
    from app.tasks.ai_validate import validate_finding_task
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    task = validate_finding_task.delay(finding_id)
    # Mark as pending immediately so the UI can show a spinner
    finding.ai_validated    = False
    finding.ai_label        = "pending"
    finding.ai_explanation  = None
    finding.ai_confidence   = None
    finding.ai_validated_at = None
    db.commit()
    return {"task_id": task.id, "status": "queued", "finding_id": finding_id}


@router.get("/{finding_id}/ai-status")
def get_ai_status(finding_id: str, db: Session = Depends(get_db)):
    """Poll the AI validation status for a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return {
        "ai_validated":    finding.ai_validated,
        "ai_confidence":   finding.ai_confidence,
        "ai_label":        finding.ai_label,
        "ai_explanation":  finding.ai_explanation,
        "ai_validated_at": finding.ai_validated_at,
    }


@router.post("/validate-batch")
def trigger_batch_validation(
    repo_id: str = Query(None),
    db: Session = Depends(get_db),
):
    """Queue AI validation for all unvalidated source-code findings (optionally filtered by repo)."""
    from app.tasks.ai_validate import validate_finding_task
    q = db.query(Finding).filter(
        Finding.source_type == "source_code",
        Finding.ai_validated == False,
        Finding.archived == False,
    )
    if repo_id:
        q = q.filter(Finding.repo_id == repo_id)
    findings = q.all()
    task_ids = []
    for f in findings:
        f.ai_label = "pending"
        task = validate_finding_task.delay(f.id)
        task_ids.append(task.id)
    db.commit()
    return {"queued": len(task_ids), "task_ids": task_ids}

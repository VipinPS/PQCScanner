from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from app.db.database import get_db
from app.models.models import Repo, Finding, CBOMEntry, ScanRun, Artifact, Project

router = APIRouter()

@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    last_scan = db.query(ScanRun).order_by(ScanRun.started_at.desc()).first()

    # ── Core counts ───────────────────────────────────────────────────────────
    total_repos    = db.query(Repo).count()
    critical_repos = db.query(Repo).filter(Repo.risk_level == "CRITICAL").count()
    total_findings = db.query(Finding).filter(Finding.archived == False).count()
    vulnerable     = db.query(Finding).filter(Finding.quantum_status == "VULNERABLE",
                                               Finding.archived == False).count()
    broken         = db.query(Finding).filter(Finding.quantum_status == "BROKEN",
                                               Finding.archived == False).count()
    safe           = db.query(Finding).filter(Finding.quantum_safe == True,
                                               Finding.archived == False).count()
    cbom_entries   = db.query(CBOMEntry).count()

    # ── 6.3: Artifact coverage ────────────────────────────────────────────────
    # Repos that have at least one completed artifact scan
    artifact_repos = (
        db.query(func.count(distinct(Artifact.repo_id)))
        .filter(Artifact.scan_status == "complete")
        .scalar() or 0
    )
    total_artifacts   = db.query(Artifact).filter(Artifact.scan_status == "complete").count()
    artifact_findings = (
        db.query(Finding)
        .filter(Finding.source_type == "artifact", Finding.archived == False)
        .count()
    )
    artifact_coverage_pct = (
        round(artifact_repos / total_repos * 100) if total_repos else 0
    )

    # ── 6.3: Call-graph coverage ──────────────────────────────────────────────
    src_findings_total = (
        db.query(Finding)
        .filter(Finding.source_type == "source_code", Finding.archived == False)
        .count()
    )
    call_graph_analyzed = (
        db.query(Finding)
        .filter(Finding.source_type == "source_code",
                Finding.archived    == False,
                Finding.reachable   != None)
        .count()
    )
    unreachable_findings = (
        db.query(Finding)
        .filter(Finding.source_type == "source_code",
                Finding.archived    == False,
                Finding.reachable   == False)
        .count()
    )
    call_graph_coverage_pct = (
        round(call_graph_analyzed / src_findings_total * 100)
        if src_findings_total else 0
    )

    return {
        # Core
        "total_repos":              total_repos,
        "critical_repos":           critical_repos,
        "total_findings":           total_findings,
        "vulnerable":               vulnerable,
        "broken":                   broken,
        "safe":                     safe,
        "cbom_entries":             cbom_entries,
        "last_scan_at":             last_scan.started_at.isoformat() if last_scan else None,
        # Artifact coverage (6.3)
        "artifact_repos":           artifact_repos,
        "total_artifacts":          total_artifacts,
        "artifact_findings":        artifact_findings,
        "artifact_coverage_pct":    artifact_coverage_pct,
        # Call-graph coverage (6.3)
        "call_graph_analyzed":      call_graph_analyzed,
        "call_graph_coverage_pct":  call_graph_coverage_pct,
        "unreachable_findings":     unreachable_findings,
    }


@router.get("/coverage-matrix")
def coverage_matrix(project_id: str = None, db: Session = Depends(get_db)):
    """
    Returns a repo × algorithm matrix for the heatmap visualisation.
    Each cell contains the worst quantum_status seen for that (repo, algorithm) pair.
    """
    q = (
        db.query(
            Repo.id, Repo.name,
            Finding.algorithm, Finding.quantum_status,
            func.count(Finding.id).label("cnt"),
        )
        .join(Finding, Finding.repo_id == Repo.id)
        .filter(
            Finding.archived          == False,
            Finding.migration_status  != "false_positive",
        )
    )
    if project_id:
        q = q.filter(Repo.project_id == project_id)

    rows = q.group_by(Repo.id, Repo.name, Finding.algorithm, Finding.quantum_status).all()

    # Priority order for worst-status resolution per cell
    _STATUS_RANK = {"BROKEN": 0, "VULNERABLE": 1, "WEAK": 2, "MONITOR": 3, "SAFE": 4}

    # Build: repo_id → {name, algorithms: {algo → {status, count}}}
    repos: dict = {}
    algorithms: set = set()

    for repo_id, repo_name, algorithm, qs, cnt in rows:
        algorithms.add(algorithm)
        if repo_id not in repos:
            repos[repo_id] = {"id": repo_id, "name": repo_name, "algorithms": {}}
        cell = repos[repo_id]["algorithms"].get(algorithm)
        # Keep worst status if same algorithm appears with different statuses
        if cell is None or _STATUS_RANK.get(qs, 99) < _STATUS_RANK.get(cell["status"], 99):
            repos[repo_id]["algorithms"][algorithm] = {"status": qs, "count": cnt}
        else:
            repos[repo_id]["algorithms"][algorithm]["count"] += cnt

    # Sort algorithms by worst average risk across repos
    def _algo_rank(algo):
        statuses = [r["algorithms"][algo]["status"] for r in repos.values() if algo in r["algorithms"]]
        return min(_STATUS_RANK.get(s, 99) for s in statuses) if statuses else 99

    sorted_algos = sorted(algorithms, key=_algo_rank)

    return {
        "repos":      list(repos.values()),
        "algorithms": sorted_algos,
    }


_STATUS_RANK = {"BROKEN": 0, "VULNERABLE": 1, "WEAK": 2, "MONITOR": 3, "SAFE": 4}


@router.get("/blast-radius")
def blast_radius(
    algorithm:  str           = Query(...),
    project_id: str | None    = None,
    db:         Session       = Depends(get_db),
):
    """
    Returns the blast radius for a given algorithm:
    how many repos and findings would be impacted if it is broken/deprecated.
    """
    cbom = db.query(CBOMEntry).filter(CBOMEntry.algorithm == algorithm).first()

    # Aggregate findings per repo for this algorithm (non-archived, non-false-positive)
    q = (
        db.query(
            Repo.id, Repo.name, Repo.risk_level,
            Finding.source_type, Finding.quantum_status,
            func.count(Finding.id).label("cnt"),
        )
        .join(Finding, Finding.repo_id == Repo.id)
        .filter(
            Finding.algorithm         == algorithm,
            Finding.archived          == False,
            Finding.migration_status  != "false_positive",
        )
    )
    if project_id:
        q = q.filter(Repo.project_id == project_id)

    rows = q.group_by(
        Repo.id, Repo.name, Repo.risk_level,
        Finding.source_type, Finding.quantum_status,
    ).all()

    repos: dict = {}
    for repo_id, repo_name, repo_risk, src_type, qs, cnt in rows:
        if repo_id not in repos:
            repos[repo_id] = {
                "id":            repo_id,
                "name":          repo_name,
                "risk_level":    repo_risk or "UNKNOWN",
                "finding_count": 0,
                "source_types":  set(),
                "worst_status":  "SAFE",
            }
        repos[repo_id]["finding_count"] += cnt
        repos[repo_id]["source_types"].add(src_type)
        if _STATUS_RANK.get(qs, 99) < _STATUS_RANK.get(repos[repo_id]["worst_status"], 99):
            repos[repo_id]["worst_status"] = qs

    repo_list = sorted(
        [
            {**r, "source_types": sorted(r["source_types"])}
            for r in repos.values()
        ],
        key=lambda r: r["finding_count"],
        reverse=True,
    )

    return {
        "algorithm":       algorithm,
        "quantum_status":  cbom.quantum_status  if cbom else None,
        "nist_replacement":cbom.nist_replacement if cbom else None,
        "algo_type":       cbom.algo_type        if cbom else None,
        "total_repos":     len(repo_list),
        "total_findings":  sum(r["finding_count"] for r in repo_list),
        "repos":           repo_list,
    }

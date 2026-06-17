"""
Runtime / eBPF agent API (Stage 12).

Routes
------
POST   /api/runtime/hosts                register a host, returns its ingest token
GET    /api/runtime/hosts                list registered hosts
DELETE /api/runtime/hosts/{host_id}      remove a host and its findings
POST   /api/runtime/ingest               agent reports aggregated findings (Bearer token auth)
GET    /api/runtime/findings             list runtime findings (paginated, filterable)
GET    /api/runtime/summary              aggregate counts for dashboard cards
PATCH  /api/runtime/findings/{id}/archive archive a runtime finding
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.models.models import RuntimeHost, RuntimeFinding, Repo
from app.scanner.engine import ALGORITHM_REGISTRY

router = APIRouter()


# ── Request / response schemas ────────────────────────────────────────────────

class RegisterHostRequest(BaseModel):
    hostname: str
    label: Optional[str] = None
    repo_id: Optional[str] = None


class IngestFinding(BaseModel):
    algorithm: str
    symbol: str
    library: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    occurrences: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class IngestRequest(BaseModel):
    hostname: str
    agent_version: Optional[str] = None
    kernel_info: Optional[str] = None
    findings: list[IngestFinding] = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _authenticate_agent(request: Request, db: Session) -> RuntimeHost:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = auth[len("Bearer "):].strip()

    host = db.query(RuntimeHost).filter(RuntimeHost.token == token).first()
    if not host:
        raise HTTPException(401, "Invalid agent token")
    return host


def _host_to_dict(h: RuntimeHost) -> dict:
    return {
        "id":            h.id,
        "hostname":      h.hostname,
        "label":         h.label,
        "repo_id":       h.repo_id,
        "agent_version": h.agent_version,
        "kernel_info":   h.kernel_info,
        "created_at":    h.created_at.isoformat() if h.created_at else None,
        "last_seen_at":  h.last_seen_at.isoformat() if h.last_seen_at else None,
    }


def _finding_to_dict(f: RuntimeFinding) -> dict:
    return {
        "id":               f.id,
        "host_id":          f.host_id,
        "hostname":         f.host.hostname if f.host else None,
        "algorithm":        f.algorithm,
        "algo_type":        f.algo_type,
        "symbol":           f.symbol,
        "library":          f.library,
        "process_name":     f.process_name,
        "pid":              f.pid,
        "occurrences":      f.occurrences,
        "risk_level":       f.risk_level,
        "quantum_status":   f.quantum_status,
        "quantum_safe":     f.quantum_safe,
        "nist_replacement": f.nist_replacement,
        "first_seen_at":    f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at":     f.last_seen_at.isoformat()  if f.last_seen_at  else None,
        "migration_status": f.migration_status,
        "archived":         f.archived,
    }


# ── Host registration ───────────────────────────────────────────────────────────

@router.post("/hosts")
def register_host(body: RegisterHostRequest, db: Session = Depends(get_db)):
    if body.repo_id:
        repo = db.query(Repo).filter(Repo.id == body.repo_id).first()
        if not repo:
            raise HTTPException(404, "Repo not found")

    host = RuntimeHost(
        hostname=body.hostname,
        label=body.label,
        repo_id=body.repo_id,
        token=secrets.token_urlsafe(32),
        created_at=datetime.utcnow(),
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    result = _host_to_dict(host)
    result["token"] = host.token
    return result


@router.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    hosts = db.query(RuntimeHost).order_by(RuntimeHost.created_at.desc()).all()
    return {"hosts": [_host_to_dict(h) for h in hosts]}


@router.delete("/hosts/{host_id}")
def delete_host(host_id: str, db: Session = Depends(get_db)):
    host = db.query(RuntimeHost).filter(RuntimeHost.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    db.delete(host)
    db.commit()
    return {"deleted": host_id}


# ── Ingest ───────────────────────────────────────────────────────────────────

@router.post("/ingest")
def ingest(body: IngestRequest, request: Request, db: Session = Depends(get_db)):
    host = _authenticate_agent(request, db)

    now = datetime.utcnow()
    host.hostname = body.hostname or host.hostname
    host.agent_version = body.agent_version or host.agent_version
    host.kernel_info = body.kernel_info or host.kernel_info
    host.last_seen_at = now

    for item in body.findings:
        info = ALGORITHM_REGISTRY.get(item.algorithm, {})

        existing = (
            db.query(RuntimeFinding)
            .filter(
                RuntimeFinding.host_id == host.id,
                RuntimeFinding.algorithm == item.algorithm,
                RuntimeFinding.symbol == item.symbol,
                RuntimeFinding.process_name == item.process_name,
                RuntimeFinding.pid == item.pid,
            )
            .first()
        )

        first_seen = item.first_seen or now
        last_seen = item.last_seen or now

        if existing:
            existing.occurrences = (existing.occurrences or 0) + max(item.occurrences, 0)
            existing.last_seen_at = last_seen
            if existing.first_seen_at is None or first_seen < existing.first_seen_at:
                existing.first_seen_at = first_seen
            existing.library = item.library or existing.library
        else:
            db.add(RuntimeFinding(
                host_id=host.id,
                algorithm=item.algorithm,
                algo_type=info.get("type"),
                symbol=item.symbol,
                library=item.library,
                process_name=item.process_name,
                pid=item.pid,
                occurrences=max(item.occurrences, 0),
                risk_level=info.get("risk"),
                quantum_status=info.get("quantum_status"),
                quantum_safe=info.get("quantum_status") in ("SAFE", "MONITOR"),
                nist_replacement=info.get("nist_replacement"),
                first_seen_at=first_seen,
                last_seen_at=last_seen,
            ))

    db.commit()
    return {"status": "ok", "host_id": host.id, "findings_ingested": len(body.findings)}


# ── Findings / dashboard ───────────────────────────────────────────────────────

@router.get("/findings")
def list_findings(
    host_id:        Optional[str] = None,
    algorithm:      Optional[str] = None,
    risk_level:     Optional[str] = None,
    quantum_status: Optional[str] = None,
    archived:       bool          = False,
    skip:           int           = Query(0, ge=0),
    limit:          int           = Query(100, ge=1, le=500),
    db:             Session       = Depends(get_db),
):
    q = db.query(RuntimeFinding).filter(RuntimeFinding.archived == archived)
    if host_id:
        q = q.filter(RuntimeFinding.host_id == host_id)
    if algorithm:
        q = q.filter(RuntimeFinding.algorithm == algorithm)
    if risk_level:
        q = q.filter(RuntimeFinding.risk_level == risk_level)
    if quantum_status:
        q = q.filter(RuntimeFinding.quantum_status == quantum_status)

    total = q.count()
    rows = (
        q.order_by(RuntimeFinding.last_seen_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "total":    total,
        "skip":     skip,
        "limit":    limit,
        "findings": [_finding_to_dict(f) for f in rows],
    }


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    base = db.query(RuntimeFinding).filter(RuntimeFinding.archived == False)

    total_hosts = db.query(func.count(RuntimeHost.id)).scalar() or 0
    total_findings = base.count()

    by_algorithm = (
        base.with_entities(RuntimeFinding.algorithm, func.count(RuntimeFinding.id))
        .group_by(RuntimeFinding.algorithm)
        .all()
    )
    by_risk = (
        base.with_entities(RuntimeFinding.risk_level, func.count(RuntimeFinding.id))
        .group_by(RuntimeFinding.risk_level)
        .all()
    )
    by_quantum_status = (
        base.with_entities(RuntimeFinding.quantum_status, func.count(RuntimeFinding.id))
        .group_by(RuntimeFinding.quantum_status)
        .all()
    )

    return {
        "total_hosts":       total_hosts,
        "total_findings":    total_findings,
        "by_algorithm":      {a: c for a, c in by_algorithm},
        "by_risk_level":     {r: c for r, c in by_risk},
        "by_quantum_status": {s: c for s, c in by_quantum_status},
    }


@router.patch("/findings/{finding_id}/archive")
def archive_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(RuntimeFinding).filter(RuntimeFinding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.archived = True
    db.commit()
    return {"archived": finding_id}

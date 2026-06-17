"""
Network / TLS endpoint scanning API.

Routes
------
GET    /api/network/              list all network findings (paginated, filterable)
POST   /api/network/scan          trigger a TLS scan of a given endpoint
DELETE /api/network/{finding_id}  delete a single finding
GET    /api/network/summary       aggregate counts for dashboard cards
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.models.models import NetworkFinding, Repo
from app.scanner.tls_scanner import scan_endpoint

router = APIRouter()


# ── Request / response schemas ────────────────────────────────────────────────

class ScanRequest(BaseModel):
    endpoint: str           # host:port  OR  https://host  OR  host (defaults 443)
    repo_id: Optional[str] = None


def _parse_endpoint(raw: str) -> tuple[str, int]:
    """Return (host, port) from user-supplied string."""
    raw = raw.strip().rstrip("/")
    # Strip scheme
    raw = re.sub(r"^https?://", "", raw)
    # Strip path
    raw = raw.split("/")[0]

    if ":" in raw:
        host, port_str = raw.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return raw, 443


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding_to_dict(f: NetworkFinding) -> dict:
    return {
        "id":               f.id,
        "endpoint":         f.endpoint,
        "repo_id":          f.repo_id,
        "scanned_at":       f.scanned_at.isoformat() if f.scanned_at else None,
        "tls_version":      f.tls_version,
        "cipher_name":      f.cipher_name,
        "cipher_bits":      f.cipher_bits,
        "cert_subject":     f.cert_subject,
        "cert_issuer":      f.cert_issuer,
        "cert_not_before":  f.cert_not_before.isoformat() if f.cert_not_before else None,
        "cert_not_after":   f.cert_not_after.isoformat()  if f.cert_not_after  else None,
        "cert_serial":      f.cert_serial,
        "key_type":         f.key_type,
        "key_size":         f.key_size,
        "key_curve":        f.key_curve,
        "sig_algorithm":    f.sig_algorithm,
        "algorithm":        f.algorithm,
        "quantum_status":   f.quantum_status,
        "risk_level":       f.risk_level,
        "nist_replacement": f.nist_replacement,
        "issues":           json.loads(f.issues) if f.issues else [],
        "scan_status":      f.scan_status,
        "error_message":    f.error_message,
        "migration_status": f.migration_status,
        "archived":         f.archived,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
def list_findings(
    repo_id:          Optional[str] = None,
    quantum_status:   Optional[str] = None,
    risk_level:       Optional[str] = None,
    scan_status:      Optional[str] = None,
    archived:         bool          = False,
    skip:             int           = Query(0, ge=0),
    limit:            int           = Query(100, ge=1, le=500),
    db:               Session       = Depends(get_db),
):
    q = db.query(NetworkFinding).filter(NetworkFinding.archived == archived)
    if repo_id:
        q = q.filter(NetworkFinding.repo_id == repo_id)
    if quantum_status:
        q = q.filter(NetworkFinding.quantum_status == quantum_status)
    if risk_level:
        q = q.filter(NetworkFinding.risk_level == risk_level)
    if scan_status:
        q = q.filter(NetworkFinding.scan_status == scan_status)

    total = q.count()
    rows  = q.order_by(NetworkFinding.scanned_at.desc()).offset(skip).limit(limit).all()

    return {
        "total":    total,
        "skip":     skip,
        "limit":    limit,
        "findings": [_finding_to_dict(f) for f in rows],
    }


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    base = db.query(NetworkFinding).filter(NetworkFinding.archived == False)

    total    = base.count()
    complete = base.filter(NetworkFinding.scan_status == "complete").count()
    failed   = base.filter(NetworkFinding.scan_status == "failed").count()

    by_status = (
        db.query(NetworkFinding.quantum_status, func.count(NetworkFinding.id))
        .filter(NetworkFinding.archived == False, NetworkFinding.scan_status == "complete")
        .group_by(NetworkFinding.quantum_status)
        .all()
    )
    by_tls = (
        db.query(NetworkFinding.tls_version, func.count(NetworkFinding.id))
        .filter(NetworkFinding.archived == False, NetworkFinding.scan_status == "complete")
        .group_by(NetworkFinding.tls_version)
        .all()
    )
    by_risk = (
        db.query(NetworkFinding.risk_level, func.count(NetworkFinding.id))
        .filter(NetworkFinding.archived == False, NetworkFinding.scan_status == "complete")
        .group_by(NetworkFinding.risk_level)
        .all()
    )

    return {
        "total":     total,
        "complete":  complete,
        "failed":    failed,
        "by_quantum_status": {s: c for s, c in by_status},
        "by_tls_version":    {v: c for v, c in by_tls},
        "by_risk_level":     {r: c for r, c in by_risk},
    }


@router.post("/scan")
def trigger_scan(body: ScanRequest, db: Session = Depends(get_db)):
    host, port = _parse_endpoint(body.endpoint)
    if not host:
        raise HTTPException(status_code=422, detail="Invalid endpoint")

    # Optional: validate repo_id exists
    if body.repo_id:
        repo = db.query(Repo).filter(Repo.id == body.repo_id).first()
        if not repo:
            raise HTTPException(status_code=404, detail="Repo not found")

    # Run synchronous scan (fast enough for on-demand use)
    res = scan_endpoint(host, port)

    finding = NetworkFinding(
        repo_id          = body.repo_id,
        endpoint         = res.endpoint,
        scanned_at       = datetime.utcnow(),
        tls_version      = res.tls_version,
        cipher_name      = res.cipher_name,
        cipher_bits      = res.cipher_bits,
        cert_subject     = res.cert_subject,
        cert_issuer      = res.cert_issuer,
        cert_not_before  = res.cert_not_before,
        cert_not_after   = res.cert_not_after,
        cert_serial      = res.cert_serial,
        key_type         = res.key_type,
        key_size         = res.key_size,
        key_curve        = res.key_curve,
        sig_algorithm    = res.sig_algorithm,
        algorithm        = res.algorithm,
        quantum_status   = res.quantum_status,
        risk_level       = res.risk_level,
        nist_replacement = res.nist_replacement,
        issues           = json.dumps(res.issues),
        scan_status      = res.scan_status,
        error_message    = res.error_message,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    return _finding_to_dict(finding)


@router.delete("/{finding_id}")
def delete_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(NetworkFinding).filter(NetworkFinding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(f)
    db.commit()
    return {"deleted": finding_id}


@router.patch("/{finding_id}/archive")
def archive_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(NetworkFinding).filter(NetworkFinding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.archived    = True
    f.archived_at = datetime.utcnow()
    db.commit()
    return {"archived": finding_id}

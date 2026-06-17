"""
Secret findings API — SSH keys, TLS certs, PKCS12, GPG, SSH config findings.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import get_db
from app.models.models import SecretFinding, Repo
from typing import Optional

router = APIRouter()

@router.get("/")
def list_secret_findings(
    repo_id:      Optional[str] = Query(None),
    project_id:   Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    risk_level:   Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    q = db.query(SecretFinding).filter(SecretFinding.archived == False)
    if project_id:
        repo_ids = [r.id for r in db.query(Repo.id).filter(Repo.project_id == project_id).all()]
        q = q.filter(SecretFinding.repo_id.in_(repo_ids))
    if repo_id:      q = q.filter(SecretFinding.repo_id      == repo_id)
    if finding_type: q = q.filter(SecretFinding.finding_type == finding_type)
    if risk_level:   q = q.filter(SecretFinding.risk_level   == risk_level)
    return q.order_by(SecretFinding.risk_level, SecretFinding.finding_type).all()

@router.get("/summary")
def secret_summary(db: Session = Depends(get_db)):
    q = db.query(SecretFinding).filter(SecretFinding.archived == False)
    findings = q.all()
    by_type  = {}
    by_risk  = {}
    expiring = 0
    for f in findings:
        by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1
        by_risk[f.risk_level]   = by_risk.get(f.risk_level,   0) + 1
        if f.expiry_status in ("EXPIRED", "EXPIRES_SOON", "EXPIRES_90D"):
            expiring += 1
    return {
        "total":    len(findings),
        "by_type":  by_type,
        "by_risk":  by_risk,
        "expiring": expiring,
    }

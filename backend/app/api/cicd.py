"""
CI/CD Integration API — Stage 8

Routes
------
GET    /api/cicd/config/{repo_id}          get gate config for a repo
PUT    /api/cicd/config/{repo_id}          save gate config (thresholds + webhook secret)
GET    /api/cicd/gate/{repo_id}            pass/fail check for CI steps
GET    /api/cicd/badge/{repo_id}.svg       shields.io-style SVG badge
POST   /api/cicd/webhook/{repo_id}         receive GitHub/GitLab push webhooks
GET    /api/cicd/deliveries/{repo_id}      list recent webhook deliveries
GET    /api/cicd/status                    overall CI gate summary across all repos
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db, SessionLocal
from app.models.models import CICDConfig, Finding, Repo, ScanRun, WebhookDelivery

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Schemas ───────────────────────────────────────────────────────────────────

class GateConfigIn(BaseModel):
    fail_on_broken:     bool = True
    fail_on_vulnerable: bool = True
    fail_on_weak:       bool = False
    fail_on_critical:   bool = True
    fail_on_high:       bool = True
    webhook_secret:     Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_or_create_config(repo_id: str, db: Session) -> CICDConfig:
    cfg = db.query(CICDConfig).filter(CICDConfig.repo_id == repo_id).first()
    if not cfg:
        cfg = CICDConfig(id=str(uuid.uuid4()), repo_id=repo_id)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _config_dict(cfg: CICDConfig) -> dict:
    return {
        "id":               cfg.id,
        "repo_id":          cfg.repo_id,
        "fail_on_broken":   cfg.fail_on_broken,
        "fail_on_vulnerable": cfg.fail_on_vulnerable,
        "fail_on_weak":     cfg.fail_on_weak,
        "fail_on_critical": cfg.fail_on_critical,
        "fail_on_high":     cfg.fail_on_high,
        "has_secret":       bool(cfg.webhook_secret),
        "updated_at":       cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


def _evaluate_gate(repo_id: str, cfg: CICDConfig, db: Session) -> dict:
    """Return gate pass/fail with per-category counts."""
    findings = (
        db.query(Finding)
        .filter(
            Finding.repo_id          == repo_id,
            Finding.archived         == False,
            Finding.migration_status.in_(["open", "re_opened"]),
        )
        .all()
    )

    counts = {
        "broken":     0, "vulnerable": 0, "weak":    0,
        "critical":   0, "high":       0,
        "total":      len(findings),
    }
    failures = []

    for f in findings:
        qs = (f.quantum_status or "").upper()
        rl = (f.risk_level     or "").upper()

        if qs == "BROKEN":
            counts["broken"] += 1
            if cfg.fail_on_broken:
                failures.append(f"BROKEN finding: {f.algorithm} in {f.file_path}:{f.line_number}")
        elif qs == "VULNERABLE":
            counts["vulnerable"] += 1
            if cfg.fail_on_vulnerable:
                failures.append(f"VULNERABLE finding: {f.algorithm} in {f.file_path}:{f.line_number}")
        elif qs == "WEAK":
            counts["weak"] += 1
            if cfg.fail_on_weak:
                failures.append(f"WEAK finding: {f.algorithm} in {f.file_path}:{f.line_number}")

        if rl == "CRITICAL" and cfg.fail_on_critical:
            if f"CRITICAL risk: {f.algorithm}" not in failures:
                counts["critical"] += 1
        elif rl == "HIGH" and cfg.fail_on_high:
            if f"HIGH risk: {f.algorithm}" not in failures:
                counts["high"] += 1

    passed = len(failures) == 0
    return {
        "passed":   passed,
        "status":   "PASS" if passed else "FAIL",
        "counts":   counts,
        "failures": failures[:20],   # cap list for large repos
        "config": {
            "fail_on_broken":     cfg.fail_on_broken,
            "fail_on_vulnerable": cfg.fail_on_vulnerable,
            "fail_on_weak":       cfg.fail_on_weak,
            "fail_on_critical":   cfg.fail_on_critical,
            "fail_on_high":       cfg.fail_on_high,
        },
    }


# ── SVG badge generator ───────────────────────────────────────────────────────

_BADGE_COLORS = {
    "PASS":    ("#42be65", "#24a148"),
    "FAIL":    ("#fa4d56", "#da1e28"),
    "UNKNOWN": ("#8d8d8d", "#6f6f6f"),
}

_RISK_BADGE_COLORS = {
    "CRITICAL": ("#fa4d56", "#da1e28"),
    "HIGH":     ("#ff832b", "#eb6200"),
    "MEDIUM":   ("#f1c21b", "#d2a106"),
    "LOW":      ("#42be65", "#24a148"),
    "UNKNOWN":  ("#8d8d8d", "#6f6f6f"),
}

def _make_badge(label: str, message: str, color_pair: tuple) -> str:
    left_color  = "#555"
    right_color = color_pair[0]
    label_w  = max(len(label)  * 6 + 10, 50)
    msg_w    = max(len(message) * 6 + 10, 40)
    total_w  = label_w + msg_w
    label_x  = label_w // 2
    msg_x    = label_w + msg_w // 2

    return f"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="{total_w}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0"  stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1"  stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="20" fill="{left_color}"/>
    <rect x="{label_w}" width="{msg_w}" height="20" fill="{right_color}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text x="{msg_x}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{msg_x}" y="14">{message}</text>
  </g>
</svg>"""


# ── Webhook dispatcher ────────────────────────────────────────────────────────

def _trigger_scan_bg(repo_id: str, delivery_id: str):
    """Run in background — creates its own DB session."""
    db = SessionLocal()
    try:
        from app.api.scans import run_scan_job
        scan_run = ScanRun(id=str(uuid.uuid4()), repo_id=repo_id, scan_type="code")
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)

        # Update delivery record
        delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
        if delivery:
            delivery.triggered_scan_id = scan_run.id
            delivery.status = "scan_queued"
            db.commit()

        run_scan_job(scan_run.id, repo_id, db)
    except Exception as exc:
        logger.exception("Webhook-triggered scan failed: %s", exc)
        delivery = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_id).first()
        if delivery:
            delivery.status = "error"
            delivery.error  = str(exc)
            db.commit()
    finally:
        db.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/config/{repo_id}")
def get_config(repo_id: str, db: Session = Depends(get_db)):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")
    cfg = _get_or_create_config(repo_id, db)
    return _config_dict(cfg)


@router.put("/config/{repo_id}")
def save_config(repo_id: str, body: GateConfigIn, db: Session = Depends(get_db)):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")
    cfg = _get_or_create_config(repo_id, db)
    cfg.fail_on_broken     = body.fail_on_broken
    cfg.fail_on_vulnerable = body.fail_on_vulnerable
    cfg.fail_on_weak       = body.fail_on_weak
    cfg.fail_on_critical   = body.fail_on_critical
    cfg.fail_on_high       = body.fail_on_high
    if body.webhook_secret is not None:
        cfg.webhook_secret = body.webhook_secret or None
    cfg.updated_at = datetime.utcnow()
    db.commit()
    return _config_dict(cfg)


@router.get("/gate/{repo_id}")
def gate_check(repo_id: str, db: Session = Depends(get_db)):
    """
    Machine-readable pass/fail for CI steps.
    Exit code hint: callers should treat 'passed: false' as a build failure.
    """
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")
    cfg  = _get_or_create_config(repo_id, db)
    result = _evaluate_gate(repo_id, cfg, db)
    result["repo_id"]   = repo_id
    result["repo_name"] = repo.name
    result["checked_at"]= datetime.utcnow().isoformat()
    return result


@router.get("/badge/{repo_id}.svg", response_class=Response)
def badge(repo_id: str, db: Session = Depends(get_db)):
    """SVG badge showing the repo's current gate status."""
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        svg = _make_badge("pqc-gate", "unknown", _BADGE_COLORS["UNKNOWN"])
        return Response(content=svg, media_type="image/svg+xml",
                        headers={"Cache-Control": "no-cache"})

    cfg    = _get_or_create_config(repo_id, db)
    result = _evaluate_gate(repo_id, cfg, db)
    label  = "pqc-gate"

    if not repo.last_scanned_at:
        svg = _make_badge(label, "not scanned", _BADGE_COLORS["UNKNOWN"])
    elif result["passed"]:
        svg = _make_badge(label, "passing", _BADGE_COLORS["PASS"])
    else:
        fail_count = len(result["failures"])
        svg = _make_badge(label, f"failing ({fail_count})", _BADGE_COLORS["FAIL"])

    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


@router.get("/risk-badge/{repo_id}.svg", response_class=Response)
def risk_badge(repo_id: str, db: Session = Depends(get_db)):
    """SVG badge showing the repo's current risk level."""
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    risk = (repo.risk_level or "UNKNOWN") if repo else "UNKNOWN"
    colors = _RISK_BADGE_COLORS.get(risk, _RISK_BADGE_COLORS["UNKNOWN"])
    svg = _make_badge("pqc-risk", risk, colors)
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


@router.post("/webhook/{repo_id}", status_code=202)
async def receive_webhook(
    repo_id:    str,
    request:    Request,
    bg:         BackgroundTasks,
    db:         Session = Depends(get_db),
    x_hub_signature_256: Optional[str] = Header(None),
    x_gitlab_token:      Optional[str] = Header(None),
    x_github_event:      Optional[str] = Header(None),
    x_gitlab_event:      Optional[str] = Header(None),
):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")

    body_bytes = await request.body()
    cfg        = _get_or_create_config(repo_id, db)

    # ── Signature verification ────────────────────────────────────────────────
    if cfg.webhook_secret:
        secret = cfg.webhook_secret.encode()

        if x_hub_signature_256:
            # GitHub HMAC-SHA256
            expected = "sha256=" + hmac.new(secret, body_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, x_hub_signature_256):
                raise HTTPException(401, "Invalid GitHub signature")

        elif x_gitlab_token:
            # GitLab uses a plain token header
            if not hmac.compare_digest(cfg.webhook_secret, x_gitlab_token):
                raise HTTPException(401, "Invalid GitLab token")

    # ── Parse payload ─────────────────────────────────────────────────────────
    try:
        payload = json.loads(body_bytes)
    except Exception:
        raise HTTPException(400, "Invalid JSON payload")

    provider   = "github" if x_github_event else ("gitlab" if x_gitlab_event else "unknown")
    event_type = x_github_event or x_gitlab_event or "unknown"
    branch     = None
    commit_sha = None

    if provider == "github":
        ref    = payload.get("ref", "")             # "refs/heads/main"
        branch = ref.replace("refs/heads/", "")
        commit_sha = payload.get("after") or payload.get("head_commit", {}).get("id")
    elif provider == "gitlab":
        ref    = payload.get("ref", "")
        branch = ref.replace("refs/heads/", "")
        commits = payload.get("commits", [])
        commit_sha = commits[0].get("id") if commits else None

    # Only trigger scans on push/merge events, not PR open/review etc.
    should_scan = event_type.lower() in (
        "push",                         # GitHub push
        "push hook",                    # GitLab Push Hook
        "merge_request",                # allow GitLab MR too
        "pull_request",                 # GitHub PR
    )

    # Optionally filter to repo's configured branch
    if branch and repo.branch and branch not in (repo.branch, ""):
        should_scan = False

    delivery = WebhookDelivery(
        id         = str(uuid.uuid4()),
        repo_id    = repo_id,
        provider   = provider,
        event_type = event_type,
        branch     = branch,
        commit_sha = commit_sha,
        status     = "scan_queued" if should_scan else "ignored",
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)

    if should_scan:
        bg.add_task(_trigger_scan_bg, repo_id, delivery.id)

    return {
        "delivery_id": delivery.id,
        "status":      delivery.status,
        "branch":      branch,
        "event":       event_type,
    }


@router.get("/deliveries/{repo_id}")
def list_deliveries(
    repo_id: str,
    limit:   int = 50,
    db:      Session = Depends(get_db),
):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")

    rows = (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.repo_id == repo_id)
        .order_by(WebhookDelivery.received_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id":               d.id,
            "received_at":      d.received_at.isoformat() if d.received_at else None,
            "provider":         d.provider,
            "event_type":       d.event_type,
            "branch":           d.branch,
            "commit_sha":       d.commit_sha,
            "triggered_scan_id":d.triggered_scan_id,
            "status":           d.status,
            "error":            d.error,
        }
        for d in rows
    ]


@router.get("/status")
def cicd_status(db: Session = Depends(get_db)):
    """Aggregate gate status across all repos."""
    repos = db.query(Repo).all()
    configs = {c.repo_id: c for c in db.query(CICDConfig).all()}

    result = []
    for repo in repos:
        cfg = configs.get(repo.id) or CICDConfig(
            repo_id=repo.id,
            fail_on_broken=True, fail_on_vulnerable=True, fail_on_weak=False,
            fail_on_critical=True, fail_on_high=True,
        )
        gate = _evaluate_gate(repo.id, cfg, db)
        result.append({
            "repo_id":       repo.id,
            "repo_name":     repo.name,
            "risk_level":    repo.risk_level,
            "last_scanned_at": repo.last_scanned_at.isoformat() if repo.last_scanned_at else None,
            "gate_status":   gate["status"],
            "passed":        gate["passed"],
            "failure_count": len(gate["failures"]),
            "counts":        gate["counts"],
        })

    return {
        "repos":        result,
        "total":        len(result),
        "passing":      sum(1 for r in result if r["passed"]),
        "failing":      sum(1 for r in result if not r["passed"] and r["last_scanned_at"]),
        "not_scanned":  sum(1 for r in result if not r["last_scanned_at"]),
    }

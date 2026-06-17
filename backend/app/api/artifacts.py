"""
Artifact API — Phase 4
Endpoints for uploading, listing, and scanning binary artifacts.
"""

import os
import uuid
import shutil
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.models import Artifact, Repo, ScanRun, Finding
from app.api.auth import require_role
from app.scanner.artifact_scanner import detect_artifact_type, scan_artifact, UPLOAD_DIR

logger = logging.getLogger(__name__)
router = APIRouter()

os.makedirs(UPLOAD_DIR, exist_ok=True)


# ── List artifacts for a repo ─────────────────────────────────────────────────

@router.get("/")
def list_artifacts(repo_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Artifact)
    if repo_id:
        q = q.filter(Artifact.repo_id == repo_id)
    return q.order_by(Artifact.uploaded_at.desc()).all()


# ── Get single artifact ───────────────────────────────────────────────────────

@router.get("/{artifact_id}")
def get_artifact(artifact_id: str, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")
    return a


# ── Upload and scan ───────────────────────────────────────────────────────────

@router.post("/upload", status_code=201)
async def upload_artifact(
    background_tasks: BackgroundTasks,
    repo_id: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _session=Depends(require_role("admin")),
):
    repo = db.query(Repo).filter(Repo.id == repo_id).first()
    if not repo:
        raise HTTPException(404, "Repo not found")

    # Save file to disk
    artifact_id = str(uuid.uuid4())
    dest_path   = os.path.join(UPLOAD_DIR, artifact_id + "_" + file.filename)
    try:
        with open(dest_path, "wb") as fh:
            shutil.copyfileobj(file.file, fh)
    finally:
        await file.close()

    file_size = os.path.getsize(dest_path)
    art_type  = detect_artifact_type(file.filename, dest_path)
    art_name  = os.path.splitext(file.filename)[0]  # human label (no extension)

    artifact = Artifact(
        id=artifact_id,
        repo_id=repo_id,
        name=art_name,
        original_filename=file.filename,
        artifact_type=art_type,
        size_bytes=file_size,
        file_path=dest_path,
        scan_status="pending",
    )
    db.add(artifact)
    db.commit()
    db.refresh(artifact)

    # Queue background scan
    background_tasks.add_task(_run_artifact_scan, artifact_id, repo_id, dest_path, art_type, art_name)

    return artifact


# ── Delete artifact ───────────────────────────────────────────────────────────

@router.delete("/{artifact_id}", status_code=204)
def delete_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
    _session=Depends(require_role("admin")),
):
    a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not a:
        raise HTTPException(404, "Artifact not found")

    # Remove file from disk
    if a.file_path and os.path.exists(a.file_path):
        try:
            os.remove(a.file_path)
        except OSError as e:
            logger.warning("Could not remove artifact file %s: %s", a.file_path, e)

    db.delete(a)
    db.commit()


# ── Background scan task ──────────────────────────────────────────────────────

def _run_artifact_scan(artifact_id: str, repo_id: str, file_path: str,
                       artifact_type: str, artifact_name: str):
    from app.db.database import SessionLocal
    from app.api.scans import rebuild_cbom

    db = SessionLocal()
    try:
        artifact = db.query(Artifact).filter(Artifact.id == artifact_id).first()
        if not artifact:
            return

        # Mark scanning
        artifact.scan_status = "scanning"
        db.commit()

        # Create a ScanRun to hold findings
        scan_run_id = str(uuid.uuid4())
        scan_run = ScanRun(
            id=scan_run_id,
            repo_id=repo_id,
            status="scanning",
            scan_type="artifact",
            artifact_id=artifact_id,
        )
        db.add(scan_run)
        db.commit()

        # Run the scanner
        dep_findings = scan_artifact(artifact_type, file_path, artifact_name)

        # Persist as Finding records
        for df in dep_findings:
            f = Finding(
                id=str(uuid.uuid4()),
                scan_run_id=scan_run_id,
                repo_id=repo_id,
                artifact_id=artifact_id,
                file_path=df.file_path,
                line_number=df.line_number or 0,
                algorithm=df.algorithm,
                algo_type=df.algo_type,
                risk_level=df.risk_level,
                quantum_status=df.quantum_status,
                quantum_safe=df.quantum_safe,
                nist_replacement=df.nist_replacement,
                context=df.context,
                source_type="artifact",
                dependency_name=df.dependency_name,
                dependency_version=df.dependency_version,
                migration_status="open",
            )
            db.add(f)

        # Finalise
        scan_run.status          = "complete"
        scan_run.total_findings  = len(dep_findings)
        scan_run.completed_at    = datetime.utcnow()
        artifact.scan_status     = "complete"
        artifact.finding_count   = len(dep_findings)
        artifact.scanned_at      = datetime.utcnow()
        db.commit()

        # Rebuild CBOM to include new artifact findings
        try:
            rebuild_cbom(db)
        except Exception as e:
            logger.warning("CBOM rebuild after artifact scan failed: %s", e)

        logger.info("Artifact scan complete: %s — %d findings", artifact_name, len(dep_findings))

    except Exception as exc:
        logger.exception("Artifact scan error for %s: %s", artifact_name, exc)
        try:
            a = db.query(Artifact).filter(Artifact.id == artifact_id).first()
            if a:
                a.scan_status = "failed"
                a.scan_error  = str(exc)
                db.commit()
            sr = db.query(ScanRun).filter(ScanRun.artifact_id == artifact_id).first()
            if sr:
                sr.status = "failed"
                sr.error_message = str(exc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()

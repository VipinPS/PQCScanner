"""
Celery tasks for repo and artifact scanning — Phase 6.1
Each task creates its own DB session so it can run inside a Celery worker
independently from the FastAPI request lifecycle.
"""

import uuid
import logging

from app.celery_app import celery
from app.db.database import SessionLocal
from app.models.models import ScanRun, Artifact

logger = logging.getLogger(__name__)


@celery.task(bind=True, name="tasks.scan_repo", max_retries=2)
def scan_repo_task(self, scan_run_id: str, repo_id: str):
    """Run a full source + dependency + call-graph scan for one repo."""
    from app.api.scans import run_scan_job
    db = SessionLocal()
    try:
        run_scan_job(scan_run_id, repo_id, db)
    except Exception as exc:
        logger.exception("Celery scan_repo_task failed for repo %s", repo_id)
        raise self.retry(exc=exc, countdown=10) from exc
    finally:
        db.close()


@celery.task(bind=True, name="tasks.scan_artifact", max_retries=2)
def scan_artifact_task(self, artifact_id: str, repo_id: str,
                       file_path: str, artifact_type: str, artifact_name: str):
    """Run an artifact scan (wheel / JAR / binary / container)."""
    from app.api.artifacts import _run_artifact_scan
    try:
        _run_artifact_scan(artifact_id, repo_id, file_path, artifact_type, artifact_name)
    except Exception as exc:
        logger.exception("Celery scan_artifact_task failed for artifact %s", artifact_id)
        raise self.retry(exc=exc, countdown=10) from exc

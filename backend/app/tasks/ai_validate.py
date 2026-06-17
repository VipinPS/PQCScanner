"""
Celery task — Phase 3.3
Runs AI validation for a single finding asynchronously via Ollama/Granite.
"""

from datetime import datetime
import logging

from app.celery_app import celery
from app.db.database import SessionLocal
from app.models.models import Finding
from app.scanner.ai_validator import validate_finding, OllamaUnavailable

logger = logging.getLogger(__name__)


@celery.task(
    name="app.tasks.ai_validate.validate_finding_task",
    queue="ai_validation",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def validate_finding_task(self, finding_id: str) -> dict:
    """
    Validate a single Finding with Granite AI.
    Persists ai_confidence, ai_label, ai_explanation, ai_validated_at to DB.
    Returns a result dict (stored in Celery result backend).
    """
    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return {"error": "Finding not found", "finding_id": finding_id}

        logger.info("AI validating finding %s (%s @ %s:%s)",
                    finding_id[:8], finding.algorithm, finding.file_path, finding.line_number)

        result = validate_finding({
            "algorithm":   finding.algorithm,
            "algo_type":   finding.algo_type,
            "file_path":   finding.file_path,
            "line_number": finding.line_number,
            "context":     finding.context or "",
        })

        finding.ai_validated    = True
        finding.ai_confidence   = result.confidence
        finding.ai_label        = result.label
        finding.ai_explanation  = result.explanation
        finding.ai_validated_at = datetime.utcnow()
        db.commit()

        logger.info("AI result for %s: label=%s confidence=%.2f",
                    finding_id[:8], result.label, result.confidence)

        return {
            "finding_id":  finding_id,
            "label":       result.label,
            "confidence":  result.confidence,
            "explanation": result.explanation,
            "model":       result.model,
        }

    except OllamaUnavailable as exc:
        logger.warning("Ollama unavailable for finding %s: %s", finding_id[:8], exc)
        # Retry up to max_retries times
        raise self.retry(exc=exc)

    except Exception as exc:
        logger.exception("AI validation failed for finding %s", finding_id[:8])
        # Store error in DB so UI can display it
        try:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if finding:
                finding.ai_validated   = True
                finding.ai_label       = "error"
                finding.ai_explanation = f"Validation error: {exc}"
                finding.ai_validated_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
        return {"error": str(exc), "finding_id": finding_id}

    finally:
        db.close()

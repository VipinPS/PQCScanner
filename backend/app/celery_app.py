from celery import Celery
from app.core.config import settings

celery = Celery(
    "pqc_platform",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.ai_validate", "app.tasks.scan_tasks"],
)

celery.conf.update(
    task_serializer   = "json",
    result_serializer = "json",
    accept_content    = ["json"],
    task_track_started = True,
    result_expires    = 3600,   # results kept for 1 hour
)

from __future__ import annotations

from celery import Celery

from .config import get_settings

settings = get_settings()

broker = settings.celery_broker_url or settings.redis_url or "redis://127.0.0.1:6379/0"
backend = settings.celery_result_backend or settings.redis_url or "redis://127.0.0.1:6379/1"

celery = Celery(
    "threatlens",
    broker=broker,
    backend=backend,
    include=["app.tasks"],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "poll-due-feeds": {
            "task": "threatlens.poll_due_feeds",
            "schedule": 120.0,
        },
        "expire-stale-indicators": {
            "task": "threatlens.expire_indicators",
            "schedule": 3600.0,
        },
        "enforce-retention": {
            "task": "threatlens.enforce_retention",
            "schedule": 86400.0,
        },
        "weekly-executive-report": {
            "task": "threatlens.weekly_report",
            "schedule": 604800.0,
        },
    },
)

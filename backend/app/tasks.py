from __future__ import annotations

import asyncio
import logging

from .celery_app import celery
from .db import session_scope
from .jobs import expire_job, poll_due_feeds, scheduled_report_job
from .retention import enforce_retention

logger = logging.getLogger("threatlens.tasks")


@celery.task(name="threatlens.poll_due_feeds")
def poll_due_feeds_task() -> None:
    asyncio.run(poll_due_feeds())


@celery.task(name="threatlens.expire_indicators")
def expire_indicators_task() -> None:
    asyncio.run(expire_job())


@celery.task(name="threatlens.weekly_report")
def weekly_report_task() -> None:
    asyncio.run(scheduled_report_job())


@celery.task(name="threatlens.enforce_retention")
def enforce_retention_task() -> dict[str, int]:
    with session_scope() as db:
        summary = enforce_retention(db)
    logger.info("Retention pass complete: %s", summary)
    return summary

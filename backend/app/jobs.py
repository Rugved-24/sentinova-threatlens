from __future__ import annotations

import asyncio
import logging
import os
from datetime import timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from .config import get_settings
from .db import session_scope
from .feeds import expire_indicators, run_feed
from .models import Feed, User
from .reporting import generate_report
from .utils import utcnow

logger = logging.getLogger("threatlens.jobs")
settings = get_settings()
scheduler = AsyncIOScheduler(timezone="UTC")
_running: set[str] = set()


async def poll_due_feeds() -> None:
    if os.getenv("THREATLENS_TESTING") == "1":
        return
    with session_scope() as db:
        feeds = db.execute(select(Feed).where(Feed.enabled.is_(True))).scalars().all()
        due = [
            feed.id
            for feed in feeds
            if feed.last_run_at is None
            or feed.last_run_at <= utcnow() - timedelta(minutes=feed.schedule_minutes)
        ][:4]
    if not due:
        return
    semaphore = asyncio.Semaphore(3)

    async def _run(feed_id: str) -> None:
        if feed_id in _running:
            return
        _running.add(feed_id)
        try:
            async with semaphore:
                await asyncio.to_thread(run_feed, feed_id)
        finally:
            _running.discard(feed_id)

    await asyncio.gather(*(_run(feed_id) for feed_id in due if feed_id not in _running))


async def expire_job() -> None:
    if os.getenv("THREATLENS_TESTING") == "1":
        return
    try:
        count = await asyncio.to_thread(expire_indicators, 90)
        if count:
            logger.info("Expired %s stale indicators", count)
    except Exception:
        logger.exception("Indicator expiry job failed")


async def scheduled_report_job() -> None:
    if os.getenv("THREATLENS_TESTING") == "1":
        return
    try:
        with session_scope() as db:
            admin = db.execute(
                select(User).where(User.role == "admin", User.is_active.is_(True)).limit(1)
            ).scalar_one_or_none()
            if admin is None:
                return
            report = generate_report(
                db,
                user=admin,
                title="Weekly Executive Threat Brief",
                kind="executive",
            )
            logger.info("Generated scheduled report %s (%s)", report.id, report.status)
    except Exception:
        logger.exception("Scheduled report generation failed")


def start_scheduler() -> AsyncIOScheduler:
    if os.getenv("THREATLENS_TESTING") == "1" or not settings.run_scheduler:
        return scheduler
    if scheduler.running:
        return scheduler
    scheduler.add_job(
        poll_due_feeds,
        "interval",
        minutes=2,
        id="feed-poller",
        max_instances=1,
        coalesce=True,
        next_run_time=utcnow() + timedelta(seconds=15),
    )
    scheduler.add_job(
        expire_job,
        "interval",
        hours=1,
        id="expiry",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        scheduled_report_job,
        "cron",
        day_of_week="mon",
        hour=6,
        minute=0,
        id="weekly-report",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Scheduler started")
    return scheduler


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select

from .config import get_settings
from .models import Notification, SecurityEvent
from .utils import utcnow

settings = get_settings()


def enforce_retention(db) -> dict[str, int]:
    """Bound operational history while leaving the append-only audit ledger intact."""
    now = utcnow()
    event_cutoff = now - timedelta(days=max(30, settings.retention_days))
    notification_cutoff = now - timedelta(days=max(7, settings.notification_retention_days))

    events = db.execute(delete(SecurityEvent).where(SecurityEvent.event_time < event_cutoff))
    notifications = db.execute(
        delete(Notification).where(Notification.created_at < notification_cutoff)
    )
    db.commit()
    return {
        "security_events_deleted": int(events.rowcount or 0),
        "notifications_deleted": int(notifications.rowcount or 0),
        "event_cutoff": event_cutoff.isoformat(),
        "notification_cutoff": notification_cutoff.isoformat(),
    }


def retention_summary(db) -> dict[str, int]:
    return {
        "security_events": len(db.execute(select(SecurityEvent.id)).scalars().all()),
        "notifications": len(db.execute(select(Notification.id)).scalars().all()),
    }

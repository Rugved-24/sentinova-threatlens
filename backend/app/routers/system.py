from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import __version__
from ..access import alert_visibility, incident_visibility, notification_visibility
from ..audit import record_audit
from ..config import get_settings
from ..db import get_db
from ..deps import get_current_user, require
from ..events import manager
from ..models import Alert, AttackTechnique, AuditLog, Feed, Incident, Indicator, Notification, User
from ..schemas import NotificationRead
from ..serializers import notification_item
from ..utils import iso, utcnow

router = APIRouter(tags=["system"])
settings = get_settings()


@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        db_status = "error"
    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": __version__,
        "database": db_status,
        "websocket_connections": manager.count,
        "demo_mode": settings.demo_mode,
        "environment": settings.app_env,
        "time": iso(utcnow()),
    }


@router.get("/ready")
def ready(response: Response, db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "not-ready", "database": "error", "time": iso(utcnow())}
    return {"status": "ready", "database": "ok", "time": iso(utcnow())}


@router.get("/meta")
def meta(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    feeds_total = db.execute(select(func.count()).select_from(Feed)).scalar_one()
    feeds_enabled = db.execute(
        select(func.count()).select_from(Feed).where(Feed.enabled.is_(True))
    ).scalar_one()
    techniques = db.execute(select(func.count()).select_from(AttackTechnique)).scalar_one()
    return {
        "data": {
            "version": __version__,
            "demo_mode": settings.demo_mode,
            "feeds_enabled": feeds_enabled,
            "feeds_total": feeds_total,
            "attack_techniques": techniques,
        }
    }


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)):
    counts = {
        "indicators": db.execute(select(func.count()).select_from(Indicator)).scalar_one(),
        "alerts_open": db.execute(
            select(func.count()).select_from(Alert).where(Alert.status.notin_(["resolved", "closed"]))
        ).scalar_one(),
        "incidents_open": db.execute(
            select(func.count()).select_from(Incident).where(Incident.status != "closed")
        ).scalar_one(),
        "audit_entries": db.execute(select(func.count()).select_from(AuditLog)).scalar_one(),
        "websocket_connections": manager.count,
    }
    body = "\n".join(
        [
            "# HELP threatlens_info Static build information",
            "# TYPE threatlens_info gauge",
            f'threatlens_info{{version="{__version__}",environment="{settings.app_env}"}} 1',
            "# TYPE threatlens_indicators_total gauge",
            f"threatlens_indicators_total {counts['indicators']}",
            "# TYPE threatlens_alerts_open gauge",
            f"threatlens_alerts_open {counts['alerts_open']}",
            "# TYPE threatlens_incidents_open gauge",
            f"threatlens_incidents_open {counts['incidents_open']}",
            "# TYPE threatlens_audit_entries_total gauge",
            f"threatlens_audit_entries_total {counts['audit_entries']}",
            "# TYPE threatlens_websocket_connections gauge",
            f"threatlens_websocket_connections {counts['websocket_connections']}",
        ]
    )
    return Response(content=body, media_type="text/plain; version=0.0.4")


@router.get("/badges")
def badges(
    user: User = Depends(require("view_dashboards")),
    db: Session = Depends(get_db),
):
    new_alerts = db.execute(
        select(func.count()).select_from(Alert).where(
            alert_visibility(user.role), Alert.status == "new"
        )
    ).scalar_one()
    open_incidents = db.execute(
        select(func.count()).select_from(Incident).where(Incident.status != "closed", incident_visibility(user.role))
    ).scalar_one()
    unread = db.execute(
        select(func.count()).select_from(Notification).where(
            Notification.user_id == user.id, Notification.read.is_(False), notification_visibility(user.role)
        )
    ).scalar_one()
    return {
        "data": {
            "new_alerts": new_alerts,
            "open_incidents": open_incidents,
            "unread_notifications": unread,
        }
    }


@router.get("/notifications")
def list_notifications(
    unread_only: bool = False,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = select(Notification).where(Notification.user_id == user.id, notification_visibility(user.role))
    if unread_only:
        query = query.where(Notification.read.is_(False))
    rows = db.execute(
        query.order_by(Notification.created_at.desc()).limit(100)
    ).scalars().all()
    return {"data": [notification_item(row) for row in rows]}


@router.patch("/notifications/read")
def mark_notifications(
    payload: NotificationRead,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    updated = 0
    if payload.all:
        updated = db.query(Notification).filter(
            Notification.user_id == user.id, Notification.read.is_(False)
        ).update({Notification.read: True})
    elif payload.ids:
        updated = db.query(Notification).filter(
            Notification.user_id == user.id, Notification.id.in_(payload.ids[:200])
        ).update({Notification.read: True})
    record_audit(
        db,
        "notification.read",
        actor=user,
        object_type="notification",
        detail={"updated": updated, "all": payload.all},
        request=request,
    )
    db.commit()
    return {"data": {"updated": updated}}

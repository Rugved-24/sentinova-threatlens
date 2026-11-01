from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..access import get_visible_incident, incident_visibility, require_visible_indicator
from ..audit import record_audit
from ..correlation import append_timeline
from ..db import get_db
from ..deps import require
from ..events import manager
from ..models import Alert, Incident, IncidentTimeline, Indicator, User
from ..schemas import IncidentCreate, IncidentUpdate, TimelineCreate
from ..serializers import alert_items, incident_items, indicator_list_items
from ..utils import iso, utcnow

router = APIRouter(tags=["incidents"])


def _get_incident(db: Session, incident_id: str, user: User, *, write: bool = False) -> Incident:
    incident = get_visible_incident(db, incident_id, user)
    if write and user.role == "analyst" and incident.owner_id != user.id:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "forbidden",
                "message": "Analysts can only modify incidents they own",
            },
        )
    return incident


def _detail(db: Session, incident: Incident) -> dict:
    base = incident_items(db, [incident])[0]
    timeline = db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == incident.id)
        .order_by(IncidentTimeline.created_at.asc())
    ).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.incident_id == incident.id)).scalars().all()
    indicator_ids = {alert.indicator_id for alert in alerts if alert.indicator_id}
    indicators = db.execute(
        select(Indicator).where(Indicator.id.in_(indicator_ids))
    ).scalars().all() if indicator_ids else []
    base["timeline"] = [
        {
            "id": entry.id,
            "event_type": entry.event_type,
            "message": entry.message,
            "actor_id": entry.actor_id,
            "indicator_id": entry.indicator_id,
            "meta": entry.meta,
            "created_at": iso(entry.created_at),
        }
        for entry in timeline
    ]
    base["alerts"] = alert_items(db, alerts)
    base["indicators"] = indicator_list_items(db, indicators)
    return base


@router.get("/incidents")
def list_incidents(
    user: User = Depends(require("read_incidents")),
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
    q: str = "",
    page: int = 1,
    size: int = 50,
):
    query = select(Incident).where(incident_visibility(user.role))
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if q:
        query = query.where(Incident.title.ilike(f"%{q[:100]}%"))
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    size = max(1, min(100, size))
    incidents = db.execute(
        query.order_by(Incident.created_at.desc()).offset((max(1, page) - 1) * size).limit(size)
    ).scalars().all()
    return {
        "data": incident_items(db, incidents),
        "meta": {"total": total, "page": page, "size": size},
    }


@router.post("/incidents", status_code=201)
def create_incident(
    payload: IncidentCreate,
    request: Request,
    user: User = Depends(require("manage_incidents")),
    db: Session = Depends(get_db),
):
    owner_id = payload.owner_id or user.id
    owner = db.get(User, owner_id)
    if owner is None or not owner.is_active:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_owner", "message": "Owner not found"},
        )
    if user.role == "analyst" and owner_id != user.id:
        raise HTTPException(
            status_code=403,
            detail={"error_code": "forbidden", "message": "Analysts may only own their incidents"},
        )
    incident = Incident(
        title=payload.title.strip(),
        summary=payload.summary,
        severity=payload.severity,
        status=payload.status,
        owner_id=owner_id,
        checklist=[
            {"id": "triage", "label": "Validate alert and indicator", "done": False},
            {"id": "scope", "label": "Identify affected assets and accounts", "done": False},
            {"id": "contain", "label": "Contain affected assets", "done": False},
            {"id": "eradicate", "label": "Eradicate threat and recover", "done": False},
            {"id": "report", "label": "Generate final incident report", "done": False},
        ],
    )
    db.add(incident)
    db.flush()
    append_timeline(
        db,
        incident.id,
        "created",
        f"Incident created by {user.name}.",
        actor_id=user.id,
    )
    record_audit(
        db,
        "incident.create",
        actor=user,
        object_type="incident",
        object_id=incident.id,
        detail={"title": incident.title, "severity": incident.severity},
        request=request,
    )
    db.commit()
    detail = _detail(db, incident)
    manager.publish(f"incidents.{incident.id}", {"action": "created", "incident": detail})
    return {"data": detail}


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    user: User = Depends(require("read_incidents")),
    db: Session = Depends(get_db),
):
    return {"data": _detail(db, _get_incident(db, incident_id, user))}


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    request: Request,
    user: User = Depends(require("manage_incidents")),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id, user, write=True)
    changes = {}
    if payload.title is not None:
        incident.title = payload.title.strip()
        changes["title"] = incident.title
    if payload.summary is not None:
        incident.summary = payload.summary
        changes["summary"] = "updated"
    if payload.severity is not None:
        incident.severity = payload.severity
        changes["severity"] = payload.severity
    if payload.status is not None:
        incident.status = payload.status
        incident.closed_at = utcnow() if payload.status == "closed" else None
        changes["status"] = payload.status
    if payload.owner_id is not None:
        owner = db.get(User, payload.owner_id)
        if owner is None:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_owner", "message": "Owner not found"},
            )
        incident.owner_id = owner.id
        changes["owner"] = owner.name
    if payload.checklist is not None:
        checklist = []
        for item in payload.checklist[:30]:
            if not isinstance(item, dict):
                continue
            checklist.append(
                {
                    "id": str(item.get("id", ""))[:32],
                    "label": str(item.get("label", ""))[:200],
                    "done": bool(item.get("done", False)),
                }
            )
        incident.checklist = checklist
        changes["checklist"] = f"{sum(1 for item in checklist if item['done'])}/{len(checklist)} done"
    incident.updated_at = utcnow()
    append_timeline(
        db,
        incident.id,
        "update",
        f"Incident updated: {', '.join(changes.keys())}.",
        actor_id=user.id,
        meta={"changes": changes},
    )
    record_audit(
        db,
        "incident.update",
        actor=user,
        object_type="incident",
        object_id=incident.id,
        detail={"changes": changes},
        request=request,
    )
    db.commit()
    detail = _detail(db, incident)
    manager.publish(
        f"incidents.{incident.id}",
        {"action": "updated", "changes": sorted(changes), "incident": detail},
    )
    return {"data": detail}


@router.get("/incidents/{incident_id}/timeline")
def get_timeline(
    incident_id: str,
    user: User = Depends(require("read_incidents")),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id, user)
    entries = db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == incident.id)
        .order_by(IncidentTimeline.created_at.asc())
    ).scalars().all()
    return {
        "data": [
            {
                "id": entry.id,
                "event_type": entry.event_type,
                "message": entry.message,
                "actor_id": entry.actor_id,
                "indicator_id": entry.indicator_id,
                "meta": entry.meta,
                "created_at": iso(entry.created_at),
            }
            for entry in entries
        ]
    }


@router.post("/incidents/{incident_id}/timeline", status_code=201)
def add_timeline_entry(
    incident_id: str,
    payload: TimelineCreate,
    request: Request,
    user: User = Depends(require("manage_incidents")),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id, user, write=True)
    if payload.indicator_id:
        require_visible_indicator(db, payload.indicator_id, user)
    entry = append_timeline(
        db,
        incident.id,
        payload.event_type,
        payload.message,
        actor_id=user.id,
        indicator_id=payload.indicator_id,
    )
    record_audit(
        db,
        "incident.timeline_add",
        actor=user,
        object_type="incident",
        object_id=incident.id,
        detail={"event_type": payload.event_type},
        request=request,
    )
    db.commit()
    payload = {
        "id": entry.id,
        "event_type": entry.event_type,
        "message": entry.message,
        "actor_id": entry.actor_id,
        "indicator_id": entry.indicator_id,
        "created_at": iso(entry.created_at),
    }
    manager.publish(
        f"incidents.{incident.id}",
        {"action": "timeline", "entry": payload},
    )
    return {"data": payload}

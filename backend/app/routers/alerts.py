from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..access import alert_visibility, get_visible_incident
from ..audit import record_audit
from ..correlation import append_timeline, create_incident_from_alert
from ..db import get_db
from ..deps import require
from ..events import manager
from ..models import Alert, AlertRule, Incident, Notification, User
from ..schemas import AlertPatch, AlertRuleIn, AlertRuleUpdate, EscalateIn
from ..serializers import alert_items, incident_items
from ..utils import iso, utcnow

router = APIRouter(tags=["alerts"])

TRANSITIONS = {
    "new": {"acknowledged", "in-progress", "resolved", "closed"},
    "acknowledged": {"in-progress", "resolved", "closed"},
    "in-progress": {"resolved", "closed"},
    "resolved": {"closed"},
    "closed": set(),
}


def _get_alert(db: Session, alert_id: str, user: User) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=404, detail={"error_code": "not_found", "message": "Alert not found"}
        )
    if db.scalar(select(Alert.id).where(Alert.id == alert_id, alert_visibility(user.role))) is None:
        raise HTTPException(
            status_code=403,
            detail={"error_code": "tlp_restricted", "message": "Alert exceeds your clearance"},
        )
    return alert


@router.get("/alerts")
def list_alerts(
    user: User = Depends(require("view_dashboards")),
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
    assignee_id: str | None = None,
    indicator_id: str | None = None,
    q: str = "",
    page: int = 1,
    size: int = 50,
):
    query = select(Alert).where(alert_visibility(user.role))
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if assignee_id:
        query = query.where(Alert.assignee_id == assignee_id)
    if indicator_id:
        query = query.where(Alert.indicator_id == indicator_id)
    if q:
        query = query.where(Alert.title.ilike(f"%{q[:100]}%"))
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    size = max(1, min(100, size))
    alerts = db.execute(
        query.order_by(Alert.score.desc(), Alert.created_at.desc())
        .offset((max(1, page) - 1) * size)
        .limit(size)
    ).scalars().all()
    counts = {
        status_value: db.execute(
            select(func.count()).select_from(Alert).where(
                alert_visibility(user.role), Alert.status == status_value
            )
        ).scalar_one()
        for status_value in ("new", "acknowledged", "in-progress", "resolved", "closed")
    }
    return {
        "data": alert_items(db, alerts),
        "meta": {"total": total, "page": page, "size": size, "counts": counts},
    }


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    payload: AlertPatch,
    request: Request,
    user: User = Depends(require("manage_alerts")),
    db: Session = Depends(get_db),
):
    alert = _get_alert(db, alert_id, user)
    changes = {}
    if payload.status and payload.status != alert.status:
        if payload.status not in TRANSITIONS.get(alert.status, set()):
            raise HTTPException(
                status_code=409,
                detail={
                    "error_code": "invalid_transition",
                    "message": f"Cannot move alert from {alert.status} to {payload.status}",
                },
            )
        alert.status = payload.status
        changes["status"] = payload.status
        if payload.status in {"acknowledged", "in-progress"}:
            alert.acknowledged_at = alert.acknowledged_at or utcnow()
        if payload.status in {"resolved", "closed"}:
            alert.resolved_at = utcnow()
    if payload.assignee_id is not None:
        if payload.assignee_id == "":
            alert.assignee_id = None
            changes["assignee"] = "unassigned"
        else:
            assignee = db.get(User, payload.assignee_id)
            if assignee is None or not assignee.is_active:
                raise HTTPException(
                    status_code=422,
                    detail={"error_code": "invalid_assignee", "message": "Assignee not found"},
                )
            if user.role == "analyst" and assignee.id != user.id:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error_code": "forbidden",
                        "message": "Analysts may only assign alerts to themselves",
                    },
                )
            _get_alert(db, alert.id, assignee)
            alert.assignee_id = assignee.id
            changes["assignee"] = assignee.name
            if assignee.id != user.id:
                db.add(
                    Notification(
                        user_id=assignee.id,
                        title="Alert assigned to you",
                        body=f"{alert.title} ({alert.score}/100)",
                        kind="assignment",
                        link=f"/analyst?alert={alert.id}",
                    )
                )
    if payload.incident_id is not None:
        if payload.incident_id == "":
            alert.incident_id = None
            changes["incident"] = None
        else:
            incident = get_visible_incident(db, payload.incident_id, user)
            alert.incident_id = incident.id
            changes["incident"] = incident.title
            append_timeline(
                db,
                incident.id,
                "alert",
                f"Alert '{alert.title}' linked manually by {user.name}.",
                actor_id=user.id,
                indicator_id=alert.indicator_id,
                meta={"alert_id": alert.id},
            )
    alert.updated_at = utcnow()
    if alert.incident_id and changes:
        append_timeline(
            db,
            alert.incident_id,
            "alert",
            f"Alert state updated: {', '.join(f'{key}={value}' for key, value in changes.items())}.",
            actor_id=user.id,
            indicator_id=alert.indicator_id,
            meta={"alert_id": alert.id, "changes": changes},
        )
    record_audit(
        db,
        "alert.update",
        actor=user,
        object_type="alert",
        object_id=alert.id,
        detail={"changes": changes},
        request=request,
    )
    db.commit()
    item = alert_items(db, [alert])[0]
    manager.publish("alerts.stream", item)
    return {"data": item}


@router.post("/alerts/{alert_id}/escalate", status_code=201)
def escalate_alert(
    alert_id: str,
    payload: EscalateIn,
    request: Request,
    user: User = Depends(require("manage_incidents")),
    db: Session = Depends(get_db),
):
    alert = _get_alert(db, alert_id, user)
    if alert.incident_id:
        incident = db.get(Incident, alert.incident_id)
        if incident:
            return {"data": incident_items(db, [incident])[0], "meta": {"existing": True}}
    incident = create_incident_from_alert(db, alert, user, title=payload.title)
    if payload.summary:
        incident.summary = payload.summary
    append_timeline(
        db,
        incident.id,
        "note",
        f"Escalated from alert by {user.name}.",
        actor_id=user.id,
        indicator_id=alert.indicator_id,
        meta={"alert": alert.title},
    )
    record_audit(
        db,
        "alert.escalate",
        actor=user,
        object_type="alert",
        object_id=alert.id,
        detail={"incident_id": incident.id},
        request=request,
    )
    db.commit()
    manager.publish("alerts.stream", alert_items(db, [alert])[0])
    return {"data": incident_items(db, [incident])[0], "meta": {"existing": False}}


@router.get("/alert-rules")
def list_rules(
    user: User = Depends(require("manage_rules")),
    db: Session = Depends(get_db),
):
    rules = db.execute(select(AlertRule).order_by(AlertRule.created_at.asc())).scalars().all()
    return {
        "data": [
            {
                "id": rule.id,
                "name": rule.name,
                "enabled": rule.enabled,
                "min_score": rule.min_score,
                "types": rule.types,
                "sources": rule.sources,
                "categories": rule.categories,
                "tlp_max": rule.tlp_max,
                "route_roles": rule.route_roles,
                "route_user_ids": rule.route_user_ids,
                "created_at": iso(rule.created_at),
            }
            for rule in rules
        ]
    }


@router.post("/alert-rules", status_code=201)
def create_rule(
    payload: AlertRuleIn,
    request: Request,
    user: User = Depends(require("manage_rules")),
    db: Session = Depends(get_db),
):
    route_user_ids = list(dict.fromkeys(payload.route_user_ids))
    if route_user_ids:
        found = set(
            db.scalars(select(User.id).where(User.id.in_(route_user_ids), User.is_active.is_(True)))
        )
        if found != set(route_user_ids):
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "invalid_route_user",
                    "message": "Route users must be active accounts",
                },
            )
    rule = AlertRule(
        name=payload.name.strip(),
        enabled=payload.enabled,
        min_score=payload.min_score,
        types=payload.types,
        sources=[source.lower() for source in payload.sources],
        categories=[category.strip().lower() for category in payload.categories if category.strip()],
        tlp_max=payload.tlp_max,
        route_roles=payload.route_roles,
        route_user_ids=route_user_ids,
        created_by=user.id,
    )
    db.add(rule)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={"error_code": "duplicate_rule", "message": "Rule name already exists"},
        ) from exc
    record_audit(
        db,
        "alert_rule.create",
        actor=user,
        object_type="alert_rule",
        object_id=rule.id,
        detail={"name": rule.name, "min_score": rule.min_score},
        request=request,
    )
    db.commit()
    return {"data": {"id": rule.id, "name": rule.name}}


@router.patch("/alert-rules/{rule_id}")
def update_rule(
    rule_id: str,
    payload: AlertRuleUpdate,
    request: Request,
    user: User = Depends(require("manage_rules")),
    db: Session = Depends(get_db),
):
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "not_found", "message": "Rule not found"},
        )
    if payload.name is not None:
        rule.name = payload.name.strip()
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.min_score is not None:
        rule.min_score = payload.min_score
    if payload.types is not None:
        rule.types = payload.types
    if payload.sources is not None:
        rule.sources = [source.lower() for source in payload.sources]
    if payload.categories is not None:
        rule.categories = [category.strip().lower() for category in payload.categories if category.strip()]
    if payload.tlp_max is not None:
        rule.tlp_max = payload.tlp_max
    if payload.route_roles is not None:
        rule.route_roles = payload.route_roles
    if payload.route_user_ids is not None:
        route_user_ids = list(dict.fromkeys(payload.route_user_ids))
        found = set(
            db.scalars(select(User.id).where(User.id.in_(route_user_ids), User.is_active.is_(True)))
        )
        if found != set(route_user_ids):
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "invalid_route_user",
                    "message": "Route users must be active accounts",
                },
            )
        rule.route_user_ids = route_user_ids
    record_audit(
        db,
        "alert_rule.update",
        actor=user,
        object_type="alert_rule",
        object_id=rule.id,
        detail={"name": rule.name, "enabled": rule.enabled},
        request=request,
    )
    db.commit()
    return {"data": {"id": rule.id, "name": rule.name, "enabled": rule.enabled}}

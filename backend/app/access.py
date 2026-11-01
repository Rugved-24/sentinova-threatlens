from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import and_, false, literal, or_, select

from .models import Alert, Incident, IncidentTimeline, Indicator, Notification
from .security import allowed_tlps, can_view_tlp, has_permission, require_permission


def incident_visibility(role):
    """An incident inherits the restrictions of its alerts and linked indicators."""
    if not has_permission(role, "read_incidents"):
        return false()
    clearance = list(allowed_tlps(role))
    restricted_indicator = (
        select(Indicator.id)
        .where(Indicator.id == Alert.indicator_id, Indicator.tlp.not_in(clearance))
        .correlate(Alert).exists()
    )
    restricted_alert = (
        select(Alert.id)
        .where(Alert.incident_id == Incident.id, or_(Alert.tlp.not_in(clearance), restricted_indicator))
        .correlate(Incident).exists()
    )
    restricted_timeline = (
        select(IncidentTimeline.id)
        .join(Indicator, Indicator.id == IncidentTimeline.indicator_id)
        .where(IncidentTimeline.incident_id == Incident.id, Indicator.tlp.not_in(clearance))
        .correlate(Incident).exists()
    )
    return and_(~restricted_alert, ~restricted_timeline)


def alert_visibility(role):
    if not has_permission(role, "view_indicators"):
        return false()
    clearance = list(allowed_tlps(role))
    indicator_visible = select(Indicator.id).where(
        Indicator.id == Alert.indicator_id, Indicator.tlp.in_(clearance),
    ).correlate(Alert).exists()
    incident_visible = select(Incident.id).where(
        Incident.id == Alert.incident_id, incident_visibility(role),
    ).correlate(Alert).exists()
    return and_(
        Alert.tlp.in_(clearance),
        or_(Alert.indicator_id.is_(None), indicator_visible),
        or_(Alert.incident_id.is_(None), incident_visible),
    )


def notification_visibility(role):
    """Resolve the links produced by alert/assignment notifications at read time."""
    if not has_permission(role, "view_indicators"):
        return false()
    indicator_visible = select(Indicator.id).where(
        Notification.link == literal("/analyst?indicator=") + Indicator.id,
        Indicator.tlp.in_(list(allowed_tlps(role))),
    ).correlate(Notification).exists()
    alert_visible = select(Alert.id).where(
        Notification.link == literal("/analyst?alert=") + Alert.id, alert_visibility(role),
    ).correlate(Notification).exists()
    return or_(indicator_visible, alert_visible)


def get_visible_incident(db, incident_id, user):
    require_permission(user, "read_incidents")
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, detail={"error_code": "not_found", "message": "Incident not found"})
    visible = db.scalar(select(Incident.id).where(Incident.id == incident_id, incident_visibility(user.role)))
    if visible is None:
        raise HTTPException(403, detail={"error_code": "tlp_restricted", "message": "Incident exceeds clearance"})
    return incident


def require_visible_indicator(db, indicator_id, user):
    item = db.get(Indicator, indicator_id)
    if item is None:
        raise HTTPException(404, detail={"error_code": "not_found", "message": "Indicator not found"})
    if not can_view_tlp(user.role, item.tlp):
        raise HTTPException(403, detail={"error_code": "tlp_restricted", "message": "Indicator exceeds clearance"})
    return item


def topic_allowed(db, user, topic):
    if not user or not user.is_active:
        return False
    if topic.startswith("user."):
        return topic == f"user.{user.id}"
    if topic == "system.health":
        return has_permission(user.role, "configure_feeds")
    if topic in {"alerts.stream", "alerts.new", "indicators.high_severity"}:
        return has_permission(user.role, "view_indicators")
    if topic == "incidents.updated":
        return has_permission(user.role, "read_incidents")
    if topic.startswith("incidents."):
        return db.scalar(
            select(Incident.id).where(Incident.id == topic.removeprefix("incidents."), incident_visibility(user.role))
        ) is not None
    return False


def event_allowed(db, user, topic, payload):
    if not topic_allowed(db, user, topic):
        return False
    if topic.startswith("indicators."):
        item = db.get(Indicator, payload.get("id")) if payload.get("id") else None
        return bool(item and can_view_tlp(user.role, item.tlp))
    if topic.startswith("alerts.") and payload.get("id"):
        return db.scalar(select(Alert.id).where(
            Alert.id == payload["id"], alert_visibility(user.role),
        )) is not None
    return True

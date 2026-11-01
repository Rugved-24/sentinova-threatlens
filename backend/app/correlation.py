from __future__ import annotations

from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .ingest import recompute_indicator
from .models import (
    Alert,
    AlertRule,
    Incident,
    IncidentTimeline,
    Indicator,
    IndicatorSource,
    Notification,
    SecurityEvent,
    User,
)
from .scoring import severity_for_score
from .security import can_view_tlp, has_permission
from .utils import TLP_ORDER, iso, utcnow


def indicators_for_events(db: Session, events: list[SecurityEvent]) -> list[Indicator]:
    """Find indicators affected by an incoming batch, including URL host matches."""
    ips = {ip for event in events for ip in (event.src_ip, event.dst_ip) if ip}
    domains = {event.domain for event in events if event.domain}
    hashes = {event.file_hash for event in events if event.file_hash}
    conditions = []
    if ips:
        conditions.append((Indicator.type == "ip") & Indicator.value.in_(ips))
    if domains:
        conditions.append((Indicator.type == "domain") & Indicator.value.in_(domains))
        conditions.append((Indicator.type == "url") & or_(
            *(Indicator.value.contains(domain, autoescape=True) for domain in domains)
        ))
    if hashes:
        conditions.append(Indicator.type.startswith("hash_") & Indicator.value.in_(hashes))
    if not conditions:
        return []
    candidates = db.scalars(select(Indicator).where(or_(*conditions))).all()
    return [item for item in candidates if item.type != "url" or urlsplit(item.value).hostname in domains]


def find_internal_events(db: Session, indicator: Indicator) -> list[SecurityEvent]:
    conditions = []
    if indicator.type == "ip":
        conditions = [
            SecurityEvent.src_ip == indicator.value,
            SecurityEvent.dst_ip == indicator.value,
        ]
    elif indicator.type == "domain":
        conditions = [SecurityEvent.domain == indicator.value]
    elif indicator.type.startswith("hash_"):
        conditions = [SecurityEvent.file_hash == indicator.value]
    elif indicator.type == "url":
        host = urlsplit(indicator.value).hostname
        if host:
            conditions = [SecurityEvent.domain == host]
    if not conditions:
        return []
    since = utcnow() - timedelta(days=90)
    return db.execute(
        select(SecurityEvent)
        .where(or_(*conditions), SecurityEvent.event_time >= since)
        .order_by(SecurityEvent.event_time.desc())
        .limit(500)
    ).scalars().all()


def correlate_indicator(db: Session, indicator: Indicator) -> list[SecurityEvent]:
    events = find_internal_events(db, indicator)
    indicator.internal_sightings = len(events)
    indicator.updated_at = utcnow()
    db.add(indicator)
    recompute_indicator(db, indicator)
    return events


def append_timeline(
    db: Session,
    incident_id: str,
    event_type: str,
    message: str,
    *,
    actor_id: str | None = None,
    indicator_id: str | None = None,
    meta: dict[str, Any] | None = None,
) -> IncidentTimeline:
    entry = IncidentTimeline(
        incident_id=incident_id,
        event_type=event_type[:32],
        message=message,
        actor_id=actor_id,
        indicator_id=indicator_id,
        meta=meta or {},
    )
    db.add(entry)
    db.flush()
    return entry


def _indicator_categories(indicator: Indicator, events: list[SecurityEvent]) -> set[str]:
    categories = {indicator.type}
    if indicator.type.startswith("hash_"):
        categories.add("malware")
    if indicator.type in {"ip", "domain", "url"}:
        categories.add("network")
    if indicator.type == "cve" or indicator.kev:
        categories.add("vulnerability")
    if indicator.kev:
        categories.add("known-exploited")
    if events:
        categories.add("internal-sighting")
    if indicator.severity_score >= 80:
        categories.add("critical-risk")
    return categories


def _rule_matches(
    rule: AlertRule,
    indicator: Indicator,
    sources: set[str],
    categories: set[str] | None = None,
) -> bool:
    if not rule.enabled or indicator.severity_score < rule.min_score:
        return False
    if rule.types and indicator.type not in rule.types:
        return False
    if rule.sources and not ({s.lower() for s in rule.sources} & sources):
        return False
    if rule.categories and not ({value.lower() for value in rule.categories} & (categories or set())):
        return False
    return TLP_ORDER.get(indicator.tlp, 2) <= TLP_ORDER.get(rule.tlp_max, 3)


def _notify(
    db: Session,
    alert: Alert,
    indicator: Indicator,
    roles: list[str],
    user_ids: list[str] | None = None,
) -> None:
    user_ids = user_ids or []
    if not roles and not user_ids:
        roles = ["admin", "responder", "analyst"]
    recipients = []
    if roles:
        recipients.append(User.role.in_(roles))
    if user_ids:
        recipients.append(User.id.in_(user_ids))
    users = db.execute(
        select(User).where(User.is_active.is_(True), or_(*recipients))
    ).scalars().all()
    for user in users:
        if not has_permission(user.role, "view_indicators") or not can_view_tlp(user.role, indicator.tlp):
            continue
        db.add(
            Notification(
                user_id=user.id,
                title=f"{alert.severity.title()} alert: {indicator.type} indicator",
                body=f"{indicator.value[:120]} scored {indicator.severity_score}/100.",
                kind="alert",
                link=f"/analyst?indicator={indicator.id}",
            )
        )


def create_alerts_for_indicator(
    db: Session, indicator: Indicator, events: list[SecurityEvent]
) -> list[Alert]:
    if indicator.status != "active" or indicator.severity_score < 40:
        return []
    sources = {
        row.lower()
        for row in db.execute(
            select(IndicatorSource.source_name).where(
                IndicatorSource.indicator_id == indicator.id
            )
        ).scalars().all()
    }
    rules = db.execute(select(AlertRule).where(AlertRule.enabled.is_(True))).scalars().all()
    created: list[Alert] = []
    severity = severity_for_score(indicator.severity_score)
    categories = _indicator_categories(indicator, events)
    for rule in rules:
        if not _rule_matches(rule, indicator, sources, categories):
            continue
        existing = db.execute(
            select(Alert).where(
                Alert.indicator_id == indicator.id,
                Alert.rule_id == rule.id,
                Alert.status != "closed",
            )
        ).scalar_one_or_none()
        if existing:
            continue
        alert = Alert(
            title=f"{severity.title()} {indicator.type} indicator detected",
            description=(
                f"{indicator.value} matched rule '{rule.name}'. "
                f"Score {indicator.severity_score}/100 with "
                f"{len(events)} internal sighting(s)."
            ),
            severity=severity,
            score=indicator.severity_score,
            status="new",
            rule_id=rule.id,
            indicator_id=indicator.id,
            tlp=indicator.tlp,
        )
        db.add(alert)
        db.flush()
        created.append(alert)
        _notify(db, alert, indicator, rule.route_roles, rule.route_user_ids)
        if indicator.severity_score >= 90 and len(events) >= 2:
            incident = _maybe_auto_incident(db, indicator, alert, events)
            if incident:
                alert.incident_id = incident.id
    return created


def _maybe_auto_incident(
    db: Session, indicator: Indicator, alert: Alert, events: list[SecurityEvent]
) -> Incident | None:
    existing_incident = db.execute(
        select(Incident).where(Incident.status != "closed", Incident.title.contains(indicator.value))
    ).scalar_one_or_none()
    if existing_incident:
        append_timeline(
            db,
            existing_incident.id,
            "correlation",
            f"Additional alert for {indicator.value} ({indicator.severity_score}/100).",
            indicator_id=indicator.id,
            meta={"alert_id": alert.id},
        )
        return existing_incident
    incident = Incident(
        title=f"Correlated exposure: {indicator.value[:180]}",
        summary=(
            f"Critical indicator {indicator.value} was observed in {len(events)} internal "
            "security event(s). Automated correlation created this investigation."
        ),
        status="open",
        severity="critical",
        checklist=[
            {"id": "triage", "label": "Validate indicator and internal sightings", "done": False},
            {"id": "scope", "label": "Scope affected hosts and identities", "done": False},
            {"id": "contain", "label": "Contain affected assets", "done": False},
            {"id": "eradicate", "label": "Remove persistence and malicious artefacts", "done": False},
            {"id": "report", "label": "Generate incident report and close", "done": False},
        ],
    )
    db.add(incident)
    db.flush()
    append_timeline(
        db,
        incident.id,
        "created",
        "Incident opened automatically by the correlation engine.",
        indicator_id=indicator.id,
        meta={"alert_id": alert.id, "sightings": len(events)},
    )
    append_timeline(
        db,
        incident.id,
        "observation",
        f"Indicator {indicator.value} matched {len(events)} internal event(s), first "
        f"at {iso(events[-1].event_time) if events else 'unknown'}.",
        indicator_id=indicator.id,
        meta={"hosts": sorted({event.host for event in events if event.host})[:20]},
    )
    return incident


def create_incident_from_alert(
    db: Session, alert: Alert, actor: User, title: str | None = None
) -> Incident:
    indicator = db.get(Indicator, alert.indicator_id) if alert.indicator_id else None
    incident = Incident(
        title=title or f"Investigation: {alert.title}",
        summary=alert.description,
        status="open",
        severity=alert.severity,
        owner_id=actor.id,
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
    alert.incident_id = incident.id
    append_timeline(
        db,
        incident.id,
        "created",
        f"Incident opened from alert '{alert.title}'.",
        actor_id=actor.id,
        indicator_id=alert.indicator_id,
        meta={"alert_id": alert.id},
    )
    if indicator:
        append_timeline(
            db,
            incident.id,
            "indicator",
            f"Linked indicator {indicator.value} (score {indicator.severity_score}/100).",
            actor_id=actor.id,
            indicator_id=indicator.id,
        )
    return incident

from __future__ import annotations

from datetime import timedelta

from app.correlation import (
    _rule_matches,
    append_timeline,
    correlate_indicator,
    create_alerts_for_indicator,
    create_incident_from_alert,
    find_internal_events,
)
from app.models import (
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
from app.utils import utcnow
from sqlalchemy import select, update


def _indicator(db, value: str, kind: str = "ip", **overrides) -> Indicator:
    values = {
        "value": value,
        "type": kind,
        "tlp": "amber",
        "status": "active",
        "last_seen": utcnow(),
    }
    values.update(overrides)
    indicator = Indicator(**values)
    db.add(indicator)
    db.flush()
    return indicator


def _event(db, **overrides) -> SecurityEvent:
    values = {
        "event_time": utcnow(),
        "event_type": "dns",
        "host": "workstation-7",
    }
    values.update(overrides)
    event = SecurityEvent(**values)
    db.add(event)
    db.flush()
    return event


def _disable_seed_rules(db) -> None:
    db.execute(update(AlertRule).values(enabled=False))
    db.flush()


def test_find_internal_events_matches_each_indicator_type(db):
    ip_value = "198.51.100.240"
    domain_value = "correlation.example"
    hash_value = "a" * 64
    url_value = "https://url-correlation.example/path"

    src_event = _event(db, src_ip=ip_value)
    dst_event = _event(db, dst_ip=ip_value)
    domain_event = _event(db, domain=domain_value)
    hash_event = _event(db, file_hash=hash_value)
    url_event = _event(db, domain="url-correlation.example")
    _event(db, event_time=utcnow() - timedelta(days=120), src_ip=ip_value)

    assert {event.id for event in find_internal_events(db, _indicator(db, ip_value))} == {
        src_event.id,
        dst_event.id,
    }
    assert [event.id for event in find_internal_events(db, _indicator(db, domain_value, "domain"))] == [
        domain_event.id
    ]
    assert [event.id for event in find_internal_events(db, _indicator(db, hash_value, "hash_sha256"))] == [
        hash_event.id
    ]
    assert [event.id for event in find_internal_events(db, _indicator(db, url_value, "url"))] == [
        url_event.id
    ]
    assert find_internal_events(db, _indicator(db, "no-host", "url")) == []
    assert find_internal_events(db, _indicator(db, "unmatched", "email")) == []


def test_correlate_indicator_updates_sightings_and_score(db):
    value = "203.0.113.240"
    _event(db, src_ip=value)
    _event(db, dst_ip=value)
    indicator = _indicator(db, value, confidence=70)

    events = correlate_indicator(db, indicator)

    assert len(events) == 2
    assert indicator.internal_sightings == 2
    assert indicator.severity_score > 0
    assert indicator.score_breakdown["components"]["sightings"] > 0


def test_rule_matching_honours_every_constraint(db):
    indicator = _indicator(db, "203.0.113.241", severity_score=95, tlp="amber")
    rule = AlertRule(
        name="correlation-rule-match",
        enabled=True,
        min_score=90,
        types=["ip"],
        sources=["feed-a"],
        tlp_max="amber",
        route_roles=[],
    )
    db.add(rule)
    db.flush()

    assert _rule_matches(rule, indicator, {"feed-a"})
    assert not _rule_matches(rule, indicator, {"feed-b"})
    assert not _rule_matches(rule, _indicator(db, "203.0.113.242", severity_score=10), {"feed-a"})
    assert not _rule_matches(rule, _indicator(db, "correlation.example", "domain", severity_score=95), {"feed-a"})
    assert not _rule_matches(rule, _indicator(db, "203.0.113.243", severity_score=95, tlp="red"), {"feed-a"})
    rule.enabled = False
    assert not _rule_matches(rule, indicator, {"feed-a"})


def test_alerts_route_notifications_and_open_incident(db):
    value = "203.0.113.244"
    indicator = _indicator(
        db,
        value,
        severity_score=95,
        confidence=95,
        malicious_ratio=1.0,
        kev=True,
    )
    db.add(IndicatorSource(indicator_id=indicator.id, source_name="Feed-A", source_confidence=95))
    _disable_seed_rules(db)
    rule = AlertRule(
        name="correlation-rule-alert",
        enabled=True,
        min_score=90,
        types=["ip"],
        sources=["feed-a"],
        tlp_max="red",
        route_roles=["analyst"],
    )
    db.add(rule)
    db.flush()
    _event(db, src_ip=value)
    _event(db, dst_ip=value)

    alerts = create_alerts_for_indicator(db, indicator, find_internal_events(db, indicator))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == "critical"
    assert alert.incident_id
    incident = db.get(Incident, alert.incident_id)
    assert incident is not None
    assert incident.title.startswith("Correlated exposure:")
    timeline = db.execute(
        select(IncidentTimeline).where(IncidentTimeline.incident_id == incident.id)
    ).scalars().all()
    assert {entry.event_type for entry in timeline} == {"created", "observation"}
    notifications = db.execute(select(Notification).where(Notification.kind == "alert")).scalars().all()
    assert any(value[:120] in item.body for item in notifications)

    assert create_alerts_for_indicator(db, indicator, find_internal_events(db, indicator)) == []


def test_auto_incident_appends_to_existing_case(db):
    value = "203.0.113.245"
    indicator = _indicator(db, value, severity_score=95, kev=True)
    db.add(IndicatorSource(indicator_id=indicator.id, source_name="Feed-A", source_confidence=95))
    existing = Incident(
        title=f"Correlated exposure: {value}",
        summary="Existing case",
        status="open",
        severity="critical",
    )
    db.add(existing)
    _disable_seed_rules(db)
    rule = AlertRule(
        name="correlation-rule-existing",
        enabled=True,
        min_score=90,
        types=["ip"],
        sources=[],
        tlp_max="red",
        route_roles=[],
    )
    db.add(rule)
    db.flush()
    _event(db, src_ip=value)
    _event(db, dst_ip=value)

    alerts = create_alerts_for_indicator(db, indicator, find_internal_events(db, indicator))

    assert len(alerts) == 1
    assert alerts[0].incident_id == existing.id
    timeline = db.execute(
        select(IncidentTimeline).where(IncidentTimeline.incident_id == existing.id)
    ).scalars().all()
    assert [entry.event_type for entry in timeline] == ["correlation"]


def test_create_incident_from_alert_links_indicator_and_timeline(db):
    indicator = _indicator(db, "203.0.113.246", severity_score=88)
    alert = Alert(
        title="High severity ip indicator detected",
        description="Test alert",
        severity="high",
        score=88,
        status="new",
        indicator_id=indicator.id,
        tlp="amber",
    )
    db.add(alert)
    db.flush()
    actor = db.execute(select(User).where(User.role == "responder")).scalars().first()

    incident = create_incident_from_alert(db, alert, actor)

    assert incident.owner_id == actor.id
    assert alert.incident_id == incident.id
    timeline = db.execute(
        select(IncidentTimeline).where(IncidentTimeline.incident_id == incident.id)
    ).scalars().all()
    assert {entry.event_type for entry in timeline} == {"created", "indicator"}


def test_append_timeline_truncates_event_type_and_defaults_meta(db):
    incident = Incident(title="Timeline test", status="open", severity="low")
    db.add(incident)
    db.flush()

    entry = append_timeline(db, incident.id, "x" * 80, "Message")

    assert len(entry.event_type) == 32
    assert entry.meta == {}
    assert entry.message == "Message"

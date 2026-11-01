from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    Alert,
    AlertRule,
    Incident,
    Indicator,
    IndicatorAttack,
    IndicatorRelationship,
    IndicatorSource,
    IndicatorTag,
    Notification,
    Report,
    Tag,
    User,
)
from .models import (
    Enrichment as IndicatorEnrichment,
)
from .security import allowed_tlps
from .utils import iso


def user_public(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "preferences": user.preferences or {},
        "last_login_at": iso(user.last_login_at),
    }


def _base(indicator: Indicator) -> dict[str, Any]:
    return {
        "id": indicator.id,
        "value": indicator.value,
        "type": indicator.type,
        "severity_score": indicator.severity_score,
        "severity": _severity_label(indicator.severity_score),
        "confidence": indicator.confidence,
        "tlp": indicator.tlp,
        "status": indicator.status,
        "first_seen": iso(indicator.first_seen),
        "last_seen": iso(indicator.last_seen),
        "country": indicator.country,
        "asn": indicator.asn,
        "internal_sightings": indicator.internal_sightings,
        "source_count": indicator.source_count,
        "kev": indicator.kev,
    }


def _severity_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _tag_map(db: Session, ids: list[str]) -> dict[str, list[dict]]:
    if not ids:
        return {}
    rows = db.execute(
        select(IndicatorTag.indicator_id, Tag.name, Tag.color)
        .join(Tag, Tag.id == IndicatorTag.tag_id)
        .where(IndicatorTag.indicator_id.in_(ids))
    ).all()
    result: dict[str, list[dict]] = defaultdict(list)
    for indicator_id, name, color in rows:
        result[indicator_id].append({"name": name, "color": color})
    return result


def _attack_map(db: Session, ids: list[str]) -> dict[str, list[str]]:
    if not ids:
        return {}
    rows = db.execute(
        select(IndicatorAttack.indicator_id, IndicatorAttack.technique_id).where(
            IndicatorAttack.indicator_id.in_(ids)
        )
    ).all()
    result: dict[str, list[str]] = defaultdict(list)
    for indicator_id, technique_id in rows:
        result[indicator_id].append(technique_id)
    return result


def indicator_list_items(db: Session, indicators: list[Indicator]) -> list[dict]:
    ids = [indicator.id for indicator in indicators]
    tags = _tag_map(db, ids)
    attacks = _attack_map(db, ids)
    items = []
    for indicator in indicators:
        item = _base(indicator)
        item["tags"] = tags.get(indicator.id, [])
        item["attack_ids"] = attacks.get(indicator.id, [])
        items.append(item)
    return items


def indicator_detail(db: Session, indicator: Indicator, *, role: str) -> dict[str, Any]:
    item = _base(indicator)
    item["notes"] = indicator.notes
    item["geo"] = indicator.geo or {}
    item["malicious_ratio"] = indicator.malicious_ratio
    item["score_breakdown"] = indicator.score_breakdown or {}
    item["created_at"] = iso(indicator.created_at)
    item["updated_at"] = iso(indicator.updated_at)
    item["tags"] = _tag_map(db, [indicator.id]).get(indicator.id, [])
    item["attack_ids"] = _attack_map(db, [indicator.id]).get(indicator.id, [])
    item["sources"] = [
        {
            "name": source.source_name,
            "confidence": source.source_confidence,
            "reliability": source.source_reliability,
            "first_seen": iso(source.first_seen),
            "last_seen": iso(source.last_seen),
            "raw_ref": source.raw_ref,
        }
        for source in db.execute(
            select(IndicatorSource)
            .where(IndicatorSource.indicator_id == indicator.id)
            .order_by(IndicatorSource.last_seen.desc())
        ).scalars().all()
    ]
    item["enrichments"] = [
        {
            "provider": row.provider,
            "kind": row.kind,
            "verdict": row.verdict,
            "score": row.score,
            "simulated": row.simulated,
            "fetched_at": iso(row.fetched_at),
            "data": row.data,
        }
        for row in db.execute(
            select(IndicatorEnrichment)
            .where(IndicatorEnrichment.indicator_id == indicator.id)
            .order_by(IndicatorEnrichment.fetched_at.desc())
            .limit(12)
        ).scalars().all()
    ]
    edges = db.execute(
        select(IndicatorRelationship).where(
            (IndicatorRelationship.source_id == indicator.id)
            | (IndicatorRelationship.target_id == indicator.id)
        ).limit(50)
    ).scalars().all()
    related_ids = {edge.source_id for edge in edges} | {edge.target_id for edge in edges}
    related_ids.discard(indicator.id)
    related = {
        row.id: row
        for row in db.execute(select(Indicator).where(
            Indicator.id.in_(related_ids), Indicator.tlp.in_(list(allowed_tlps(role))),
        )).scalars().all()
    } if related_ids else {}
    item["relationships"] = [
        {
            "id": edge.id,
            "relation_type": edge.relation_type,
            "direction": "out" if edge.source_id == indicator.id else "in",
            "confidence": edge.confidence,
            "other": {
                "id": related[edge.target_id if edge.source_id == indicator.id else edge.source_id].id,
                "value": related[
                    edge.target_id if edge.source_id == indicator.id else edge.source_id
                ].value,
                "type": related[
                    edge.target_id if edge.source_id == indicator.id else edge.source_id
                ].type,
                "severity_score": related[
                    edge.target_id if edge.source_id == indicator.id else edge.source_id
                ].severity_score,
            },
        }
        for edge in edges
        if (edge.target_id if edge.source_id == indicator.id else edge.source_id) in related
    ]
    return item


def alert_items(db: Session, alerts: list[Alert]) -> list[dict]:
    if not alerts:
        return []
    indicator_ids = {alert.indicator_id for alert in alerts if alert.indicator_id}
    user_ids = {alert.assignee_id for alert in alerts if alert.assignee_id}
    incident_ids = {alert.incident_id for alert in alerts if alert.incident_id}
    rule_ids = {alert.rule_id for alert in alerts if alert.rule_id}
    indicators = {
        row.id: row
        for row in db.execute(select(Indicator).where(Indicator.id.in_(indicator_ids))).scalars().all()
    } if indicator_ids else {}
    users = {
        row.id: row
        for row in db.execute(select(User).where(User.id.in_(user_ids))).scalars().all()
    } if user_ids else {}
    incidents = {
        row.id: row
        for row in db.execute(select(Incident).where(Incident.id.in_(incident_ids))).scalars().all()
    } if incident_ids else {}
    rules = {
        row.id: row
        for row in db.execute(select(AlertRule).where(AlertRule.id.in_(rule_ids))).scalars().all()
    } if rule_ids else {}
    items = []
    for alert in alerts:
        indicator = indicators.get(alert.indicator_id)
        items.append(
            {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "score": alert.score,
                "status": alert.status,
                "tlp": alert.tlp,
                "created_at": iso(alert.created_at),
                "updated_at": iso(alert.updated_at),
                "acknowledged_at": iso(alert.acknowledged_at),
                "resolved_at": iso(alert.resolved_at),
                "rule": rules[alert.rule_id].name if alert.rule_id in rules else None,
                "assignee": (
                    {"id": users[alert.assignee_id].id, "name": users[alert.assignee_id].name}
                    if alert.assignee_id in users
                    else None
                ),
                "incident": (
                    {"id": incidents[alert.incident_id].id, "title": incidents[alert.incident_id].title}
                    if alert.incident_id in incidents
                    else None
                ),
                "indicator": (
                    {
                        "id": indicator.id,
                        "value": indicator.value,
                        "type": indicator.type,
                        "severity_score": indicator.severity_score,
                        "internal_sightings": indicator.internal_sightings,
                    }
                    if indicator
                    else None
                ),
            }
        )
    return items


def incident_items(db: Session, incidents: list[Incident]) -> list[dict]:
    user_ids = {incident.owner_id for incident in incidents if incident.owner_id}
    users = {
        row.id: row
        for row in db.execute(select(User).where(User.id.in_(user_ids))).scalars().all()
    } if user_ids else {}
    items = []
    for incident in incidents:
        alert_count = db.execute(
            select(func.count()).select_from(Alert).where(Alert.incident_id == incident.id)
        ).scalar_one()
        indicator_count = db.execute(
            select(func.count(func.distinct(Alert.indicator_id))).where(
                Alert.incident_id == incident.id, Alert.indicator_id.is_not(None)
            )
        ).scalar_one()
        checklist = incident.checklist or []
        items.append(
            {
                "id": incident.id,
                "title": incident.title,
                "summary": incident.summary,
                "status": incident.status,
                "severity": incident.severity,
                "owner": (
                    {"id": users[incident.owner_id].id, "name": users[incident.owner_id].name}
                    if incident.owner_id in users
                    else None
                ),
                "checklist": checklist,
                "checklist_done": sum(1 for item in checklist if item.get("done")),
                "checklist_total": len(checklist),
                "alert_count": alert_count,
                "indicator_count": indicator_count,
                "created_at": iso(incident.created_at),
                "updated_at": iso(incident.updated_at),
                "closed_at": iso(incident.closed_at),
            }
        )
    return items


def feed_items(db: Session, feeds) -> list[dict]:
    return [
        {
            "id": feed.id,
            "name": feed.name,
            "kind": feed.kind,
            "url": feed.url,
            "has_auth": bool(feed.auth_header_enc),
            "enabled": feed.enabled,
            "schedule_minutes": feed.schedule_minutes,
            "last_run_at": iso(feed.last_run_at),
            "last_status": feed.last_status,
            "last_error": feed.last_error,
            "indicator_count": feed.indicator_count,
            "config": feed.config or {},
            "created_at": iso(feed.created_at),
        }
        for feed in feeds
    ]


def report_item(report: Report) -> dict:
    return {
        "id": report.id,
        "title": report.title,
        "kind": report.kind,
        "status": report.status,
        "requested_by": report.requested_by,
        "created_at": iso(report.created_at),
        "completed_at": iso(report.completed_at),
        "download_url": f"/api/v1/reports/{report.id}/download" if report.storage_path else None,
    }


def notification_item(notification: Notification) -> dict:
    return {
        "id": notification.id,
        "title": notification.title,
        "body": notification.body,
        "kind": notification.kind,
        "read": notification.read,
        "link": notification.link,
        "created_at": iso(notification.created_at),
    }


def audit_item(row) -> dict:
    return {
        "id": row.id,
        "ts": iso(row.ts),
        "actor_email": row.actor_email,
        "action": row.action,
        "object_type": row.object_type,
        "object_id": row.object_id,
        "ip": row.ip,
        "correlation_id": row.correlation_id,
        "detail": row.detail,
        "entry_hash": row.entry_hash,
        "prev_hash": row.prev_hash,
    }


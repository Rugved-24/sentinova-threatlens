from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, time, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    Alert,
    AttackTechnique,
    Incident,
    Indicator,
    IndicatorAttack,
    IndicatorSource,
    SecurityEvent,
    User,
)
from .security import allowed_tlps
from .serializers import alert_items, indicator_list_items
from .utils import iso, utcnow

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "defense-impairment", "credential-access",
    "discovery", "lateral-movement", "collection", "stealth", "command-and-control",
    "exfiltration", "impact",
]

COUNTRY_COORDS = {
    "US": (39.8, -98.6), "IN": (20.6, 79.0), "DE": (51.2, 10.4), "SG": (1.35, 103.8),
    "GB": (55.4, -3.4), "AU": (-25.3, 133.8), "JP": (36.2, 138.3), "BR": (-14.2, -51.9),
    "CN": (35.9, 104.2), "RU": (61.5, 105.3), "NL": (52.1, 5.3), "FR": (46.2, 2.2),
    "CA": (56.1, -106.3), "ZA": (-30.6, 22.9), "AE": (23.4, 53.8), "KR": (35.9, 127.8),
}


def _visible(role: str):
    clearance = allowed_tlps(role)
    if role == "executive":
        return None
    return clearance


def geo_overview(db: Session, role: str) -> dict:
    rows = db.execute(visible_indicators(db, role)).scalars().all()
    points: dict[str, dict] = {}
    for indicator in rows:
        geo = indicator.geo or {}
        code = str(geo.get("country_code") or indicator.country or "").upper()
        if not code:
            continue
        point = points.setdefault(
            code,
            {
                "country_code": code,
                "country_name": geo.get("country_name") or code,
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "count": 0,
                "critical": 0,
                "high": 0,
                "score_total": 0,
                "simulated": bool(geo.get("simulated")),
            },
        )
        point["count"] += 1
        point["score_total"] += indicator.severity_score
        if indicator.severity_score >= 80:
            point["critical"] += 1
        elif indicator.severity_score >= 60:
            point["high"] += 1
        if not point["latitude"] or not point["longitude"]:
            coords = COUNTRY_COORDS.get(code)
            if coords:
                point["latitude"], point["longitude"] = coords
    result = []
    for point in points.values():
        coords = COUNTRY_COORDS.get(point["country_code"], (0.0, 0.0))
        point["latitude"] = point["latitude"] or coords[0]
        point["longitude"] = point["longitude"] or coords[1]
        point["avg_score"] = round(point.pop("score_total") / max(1, point["count"]), 1)
        result.append(point)
    result.sort(key=lambda item: (-item["count"], -item["critical"]))
    return {"points": result, "total": sum(item["count"] for item in result)}


def visible_indicators(db: Session, role: str):
    query = select(Indicator).where(Indicator.status == "active")
    clearance = _visible(role)
    if clearance is not None:
        query = query.where(Indicator.tlp.in_(list(clearance) or ["__none__"]))
    return query


def _risk_score(avg: float, critical_ratio: float) -> int:
    return int(round(max(0.0, min(100.0, avg * 0.75 + critical_ratio * 25.0))))


def executive_overview(db: Session, role: str) -> dict:
    query = visible_indicators(db, role)
    indicators = db.execute(query.order_by(Indicator.severity_score.desc())).scalars().all()
    total = len(indicators)
    counts = Counter(_severity(indicator.severity_score) for indicator in indicators)
    avg = sum(indicator.severity_score for indicator in indicators) / total if total else 0
    critical_ratio = counts.get("critical", 0) / total if total else 0
    risk = _risk_score(avg, critical_ratio)

    since = utcnow() - timedelta(days=29)
    clearance = _visible(role)
    trend_filter = [Indicator.first_seen >= since]
    if clearance is not None:
        trend_filter.append(Indicator.tlp.in_(list(clearance) or ["__none__"]))
    trend_rows = {
        (key.isoformat() if hasattr(key, "isoformat") else str(key)): value
        for key, value in db.execute(
            select(func.date(Indicator.first_seen), func.avg(Indicator.severity_score))
            .where(*trend_filter)
            .group_by(func.date(Indicator.first_seen))
        ).all()
    }
    trend = []
    for offset in range(30):
        day = (utcnow() - timedelta(days=29 - offset)).date()
        key = day.isoformat()
        day_start = datetime.combine(day, time.min)
        trend.append(
            {
                "date": key,
                "count": db.execute(
                    select(func.count()).select_from(Indicator).where(
                        *trend_filter,
                        Indicator.first_seen >= day_start,
                        Indicator.first_seen < day_start + timedelta(days=1),
                    )
                ).scalar_one(),
                "avg_score": round(float(trend_rows.get(key) or 0), 1),
            }
        )

    types = Counter(indicator.type for indicator in indicators)
    source_query = (
        select(IndicatorSource.source_name, func.count(func.distinct(IndicatorSource.indicator_id)))
        .join(Indicator, Indicator.id == IndicatorSource.indicator_id)
        .where(Indicator.status == "active")
    )
    if clearance is not None:
        source_query = source_query.where(
            Indicator.tlp.in_(list(clearance) or ["__none__"])
        )
    source_rows = db.execute(
        source_query.group_by(IndicatorSource.source_name)
        .order_by(func.count().desc())
        .limit(10)
    ).all()

    country_counts: Counter = Counter()
    country_scores: dict[str, list[int]] = defaultdict(list)
    country_coords: dict[str, tuple[float, float]] = {}
    for indicator in indicators:
        if not indicator.country:
            continue
        country_counts[indicator.country] += 1
        country_scores[indicator.country].append(indicator.severity_score)
        geo = indicator.geo or {}
        if geo.get("latitude") is not None and geo.get("longitude") is not None:
            country_coords.setdefault(
                indicator.country, (float(geo["latitude"]), float(geo["longitude"]))
            )
    heatmap = []
    for country, count in country_counts.most_common(40):
        lat, lon = country_coords.get(country, COUNTRY_COORDS.get(country, (0, 0)))
        heatmap.append(
            {
                "country": country,
                "count": count,
                "avg_score": round(
                    sum(country_scores[country]) / max(1, len(country_scores[country])), 1
                ),
                "latitude": lat,
                "longitude": lon,
            }
        )
    target_counts = dict(
        db.execute(
            select(SecurityEvent.country, func.count())
            .where(SecurityEvent.country.is_not(None))
            .group_by(SecurityEvent.country)
        ).all()
    )
    targets = [
        {
            "country": code,
            "count": count,
            "latitude": COUNTRY_COORDS.get(code, (0, 0))[0],
            "longitude": COUNTRY_COORDS.get(code, (0, 0))[1],
        }
        for code, count in sorted(target_counts.items(), key=lambda item: item[1], reverse=True)[:25]
    ]

    alert_filter = [] if clearance is None else [Alert.tlp.in_(list(clearance))]
    alert_counts = Counter(
        dict(
            db.execute(
                select(Alert.status, func.count()).where(*alert_filter).group_by(Alert.status)
            ).all()
        )
    )
    throughput = []
    for offset in range(13, -1, -1):
        day_value = (utcnow() - timedelta(days=offset)).date()
        day = day_value.isoformat()
        day_start = datetime.combine(day_value, time.min)
        day_end = day_start + timedelta(days=1)
        throughput.append(
            {
                "date": day,
                "raised": db.execute(
                    select(func.count()).select_from(Alert).where(
                        *alert_filter,
                        Alert.created_at >= day_start,
                        Alert.created_at < day_end,
                    )
                ).scalar_one(),
                "resolved": db.execute(
                    select(func.count()).select_from(Alert).where(
                        *alert_filter,
                        Alert.resolved_at.is_not(None),
                        Alert.resolved_at >= day_start,
                        Alert.resolved_at < day_end,
                    )
                ).scalar_one(),
            }
        )

    open_incidents = db.execute(
        select(func.count()).select_from(Incident).where(Incident.status != "closed")
    ).scalar_one()
    top = [] if role == "executive" else indicator_list_items(db, indicators[:8])
    attack_query = (
        select(IndicatorAttack.technique_id, func.count(IndicatorAttack.indicator_id))
        .join(Indicator, Indicator.id == IndicatorAttack.indicator_id)
        .where(Indicator.status == "active")
    )
    if clearance is not None:
        attack_query = attack_query.where(
            Indicator.tlp.in_(list(clearance) or ["__none__"])
        )
    attack_top = [
        {"technique_id": row[0], "count": row[1]}
        for row in db.execute(
            attack_query.group_by(IndicatorAttack.technique_id)
            .order_by(func.count().desc())
            .limit(8)
        ).all()
    ]
    return {
        "risk_score": risk,
        "risk_trend": _risk_trend(trend),
        "counts": {
            "active": total,
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "kev": sum(1 for indicator in indicators if indicator.kev),
            "sightings": sum(indicator.internal_sightings for indicator in indicators),
            "open_incidents": open_incidents,
            "open_alerts": sum(
                count for status, count in alert_counts.items() if status not in {"resolved", "closed"}
            ),
        },
        "trend": trend,
        "categories": [{"value": key, "count": value} for key, value in types.most_common()],
        "top_sources": [{"value": row[0], "count": row[1]} for row in source_rows],
        "heatmap": heatmap,
        "targets": targets,
        "alert_status": [{"value": key, "count": value} for key, value in alert_counts.items()],
        "alert_throughput": throughput,
        "attack_top": attack_top,
        "top_indicators": top,
        "generated_at": iso(utcnow()),
    }


def _risk_trend(trend: list[dict]) -> list[dict]:
    result = []
    for index, point in enumerate(trend):
        window = trend[max(0, index - 6) : index + 1]
        avg = sum(item["avg_score"] for item in window) / max(1, len(window))
        result.append({"date": point["date"], "score": round(avg, 1)})
    return result


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def analyst_overview(db: Session, user: User) -> dict:
    visible = visible_indicators(db, user.role).subquery()
    visible_ids = select(visible.c.id)
    clearance = list(allowed_tlps(user.role)) or ["__none__"]
    alert_query = select(Alert).where(Alert.tlp.in_(clearance))
    alert_rows = db.execute(
        alert_query.order_by(Alert.score.desc(), Alert.created_at.desc()).limit(40)
    ).scalars().all()

    def _count(*conditions) -> int:
        return db.execute(
            select(func.count()).select_from(Alert).where(Alert.tlp.in_(clearance), *conditions)
        ).scalar_one()

    counters = {
        "new": _count(Alert.status == "new"),
        "unassigned": _count(Alert.assignee_id.is_(None)),
        "mine": _count(Alert.assignee_id == user.id),
        "open": _count(Alert.status.notin_(["resolved", "closed"])),
        "today": _count(Alert.created_at >= utcnow() - timedelta(days=1)),
    }
    recent_indicators = db.execute(
        select(Indicator)
        .where(Indicator.id.in_(visible_ids))
        .order_by(Indicator.first_seen.desc())
        .limit(10)
    ).scalars().all()
    return {
        "counters": counters,
        "queue": alert_items(db, alert_rows[:30]),
        "recent_indicators": indicator_list_items(db, recent_indicators),
        "generated_at": iso(utcnow()),
    }


def attack_matrix(db: Session, role: str) -> dict:
    total_by_tactic = dict(
        db.execute(
            select(AttackTechnique.tactic, func.count()).group_by(AttackTechnique.tactic)
        ).all()
    )
    attack_query = (
        select(
            AttackTechnique.id,
            AttackTechnique.name,
            AttackTechnique.tactic,
            func.count(IndicatorAttack.indicator_id),
        )
        .join(IndicatorAttack, IndicatorAttack.technique_id == AttackTechnique.id)
        .join(Indicator, Indicator.id == IndicatorAttack.indicator_id)
        .where(Indicator.status == "active")
    )
    clearance = _visible(role)
    if clearance is not None:
        attack_query = attack_query.where(
            Indicator.tlp.in_(list(clearance) or ["__none__"])
        )
    mapped = db.execute(
        attack_query.group_by(AttackTechnique.id)
        .order_by(func.count(IndicatorAttack.indicator_id).desc())
    ).all()
    technique_counts = Counter({row[0]: row[3] for row in mapped})
    by_tactic: dict[str, list[dict]] = defaultdict(list)
    for technique_id, name, tactic, count in mapped:
        by_tactic[tactic].append(
            {"id": technique_id, "name": name, "count": count}
        )
    tactics = []
    for tactic in TACTIC_ORDER:
        techniques = by_tactic.get(tactic, [])
        tactics.append(
            {
                "id": tactic,
                "name": tactic.replace("-", " ").title(),
                "mapped": len(techniques),
                "total": total_by_tactic.get(tactic, 0),
                "count": sum(techniques[index]["count"] for index in range(len(techniques))),
                "techniques": techniques[:12],
            }
        )
    return {
        "tactics": tactics,
        "mapped_techniques": len(technique_counts),
        "total_techniques": sum(total_by_tactic.values()),
    }


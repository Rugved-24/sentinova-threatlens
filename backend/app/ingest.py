from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import refresh_fts_row
from .models import (
    AttackTechnique,
    Indicator,
    IndicatorAttack,
    IndicatorRelationship,
    IndicatorSource,
    IndicatorTag,
    Tag,
)
from .normalize import canonicalize, normalize_tlp
from .scoring import compute_score
from .utils import most_restrictive_tlp_value, sha256, utcnow

TAG_PALETTE = ["#38bdf8", "#a78bfa", "#f472b6", "#fb923c", "#34d399", "#facc15", "#f87171"]


def _tag_color(name: str) -> str:
    return TAG_PALETTE[int(sha256(name)[:8], 16) % len(TAG_PALETTE)]


def attach_tag(db: Session, indicator_id: str, name: str) -> None:
    clean = " ".join(name.strip().lower().split())[:64]
    if not clean:
        return
    tag = db.execute(select(Tag).where(Tag.name == clean)).scalar_one_or_none()
    if tag is None:
        tag = Tag(name=clean, color=_tag_color(clean))
        db.add(tag)
        db.flush()
    exists = db.get(IndicatorTag, {"indicator_id": indicator_id, "tag_id": tag.id})
    if exists is None:
        db.add(IndicatorTag(indicator_id=indicator_id, tag_id=tag.id))


def attach_attack(db: Session, indicator_id: str, technique_ids: list[str] | None) -> None:
    for technique_id in technique_ids or []:
        tid = technique_id.strip().upper()[:16]
        if not tid or db.get(AttackTechnique, tid) is None:
            continue
        if db.get(IndicatorAttack, {"indicator_id": indicator_id, "technique_id": tid}) is None:
            db.add(IndicatorAttack(indicator_id=indicator_id, technique_id=tid))


def recompute_indicator(db: Session, indicator: Indicator) -> None:
    sources = db.execute(
        select(IndicatorSource).where(IndicatorSource.indicator_id == indicator.id)
    ).scalars().all()
    if sources:
        weight = sum(max(0.05, source.source_reliability) for source in sources)
        confidence = sum(
            source.source_confidence * max(0.05, source.source_reliability) for source in sources
        ) / weight
        reliability = max(source.source_reliability for source in sources)
    else:
        confidence, reliability = 50.0, 0.7
    attack_count = db.execute(
        select(func.count()).select_from(IndicatorAttack).where(
            IndicatorAttack.indicator_id == indicator.id
        )
    ).scalar_one()
    result = compute_score(
        source_confidence=int(round(confidence)),
        last_seen=indicator.last_seen,
        source_reliability=reliability,
        internal_sightings=indicator.internal_sightings,
        malicious_ratio=indicator.malicious_ratio,
        kev=indicator.kev,
        attack_count=int(attack_count),
        status=indicator.status,
    )
    indicator.severity_score = result["score"]
    indicator.confidence = result["confidence"]
    indicator.source_count = max(1, len(sources))
    indicator.score_breakdown = {
        "components": result["components"],
        "reasons": result["reasons"],
        "model": result["model"],
        "age_days": result.get("age_days", 0),
        "source_confidence": int(round(confidence)),
        "source_reliability": round(reliability, 3),
        "attack_count": int(attack_count),
        "scored_at": utcnow().isoformat(),
    }
    indicator.updated_at = utcnow()
    db.add(indicator)
    refresh_fts_row(db, indicator.id)


def upsert_indicator(
    db: Session,
    *,
    value: str,
    kind: str | None = None,
    source: str,
    feed_id: str | None = None,
    confidence: int = 60,
    reliability: float = 0.8,
    tlp: str = "amber",
    tags: list[str] | None = None,
    attack_ids: list[str] | None = None,
    notes: str | None = None,
    raw_ref: str | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    kev: bool = False,
    geo: dict[str, Any] | None = None,
    malicious_ratio: float | None = None,
    country: str | None = None,
    asn: str | None = None,
    authorize: Callable[[Indicator], object] | None = None,
) -> tuple[Indicator | None, bool]:
    normalized = canonicalize(value, kind)
    if normalized is None:
        return None, False
    canonical_value, indicator_type = normalized
    now = utcnow()
    first = first_seen or now
    last = last_seen or now
    safe_tlp = normalize_tlp(tlp)

    indicator = db.execute(
        select(Indicator).where(
            Indicator.value == canonical_value, Indicator.type == indicator_type
        )
    ).scalar_one_or_none()
    if indicator is not None and authorize is not None:
        authorize(indicator)
    created = indicator is None
    if created:
        indicator = Indicator(
            value=canonical_value,
            type=indicator_type,
            first_seen=first,
            last_seen=last,
            tlp=safe_tlp,
            status="active",
            kev=kev,
            notes=notes,
        )
        db.add(indicator)
        db.flush()
    else:
        indicator.first_seen = min(indicator.first_seen, first)
        indicator.last_seen = max(indicator.last_seen, last)
        indicator.tlp = most_restrictive_tlp_value([indicator.tlp, safe_tlp])
        indicator.kev = indicator.kev or kev
        if notes and notes.strip() and notes.strip() not in (indicator.notes or ""):
            combined = f"{indicator.notes}\n{notes.strip()}" if indicator.notes else notes.strip()
            indicator.notes = combined[:4000]

    provenance = db.execute(
        select(IndicatorSource).where(
            IndicatorSource.indicator_id == indicator.id,
            IndicatorSource.source_name == source,
        )
    ).scalar_one_or_none()
    if provenance is None:
        db.add(
            IndicatorSource(
                indicator_id=indicator.id,
                feed_id=feed_id,
                source_name=source[:120],
                source_confidence=max(0, min(100, int(confidence))),
                source_reliability=max(0.0, min(1.0, float(reliability))),
                first_seen=first,
                last_seen=last,
                raw_ref=(raw_ref or "")[:500] or None,
            )
        )
    else:
        provenance.last_seen = max(provenance.last_seen, last)
        provenance.first_seen = min(provenance.first_seen, first)
        provenance.source_confidence = max(provenance.source_confidence, int(confidence))
        provenance.source_reliability = max(provenance.source_reliability, float(reliability))
        if raw_ref:
            provenance.raw_ref = raw_ref[:500]

    for tag in tags or []:
        attach_tag(db, indicator.id, tag)
    attach_attack(db, indicator.id, attack_ids)
    if geo:
        indicator.geo = geo
    if country:
        indicator.country = country[:64]
    if asn:
        indicator.asn = asn[:160]
    if malicious_ratio is not None:
        indicator.malicious_ratio = max(indicator.malicious_ratio, min(1.0, malicious_ratio))
    if indicator.status == "expired":
        indicator.status = "active"
    db.flush()
    recompute_indicator(db, indicator)
    return indicator, created


def add_relationship(
    db: Session,
    source_indicator: Indicator,
    target_value: str,
    target_kind: str,
    relation_type: str,
    *,
    source_name: str,
    feed_id: str | None = None,
    confidence: int = 60,
    reliability: float = 0.8,
    tlp: str = "amber",
    authorize: Callable[[Indicator], object] | None = None,
) -> None:
    target, _ = upsert_indicator(
        db,
        value=target_value,
        kind=target_kind,
        source=source_name,
        feed_id=feed_id,
        confidence=confidence,
        reliability=reliability,
        tlp=tlp,
        authorize=authorize,
    )
    if target is None or target.id == source_indicator.id:
        return
    edge = db.execute(
        select(IndicatorRelationship).where(
            IndicatorRelationship.source_id == source_indicator.id,
            IndicatorRelationship.target_id == target.id,
            IndicatorRelationship.relation_type == relation_type,
        )
    ).scalar_one_or_none()
    if edge is None:
        db.add(
            IndicatorRelationship(
                source_id=source_indicator.id,
                target_id=target.id,
                relation_type=relation_type[:32],
                confidence=max(0, min(100, confidence)),
            )
        )

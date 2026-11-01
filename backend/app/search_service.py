from __future__ import annotations

import re
from typing import Any

from sqlalchemy import false, func, select, text
from sqlalchemy.orm import Session

from .config import get_settings
from .db import IS_SQLITE
from .models import (
    Indicator,
    IndicatorAttack,
    IndicatorSource,
    IndicatorTag,
    SecurityEvent,
    Tag,
)
from .security import allowed_tlps
from .utils import iso

settings = get_settings()


def fts_query(raw: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_.:/-]{1,64}", raw or "")
    return " AND ".join(f'"{token.replace(chr(34), "")}"*' for token in tokens[:8])


def search_indicators(
    db: Session,
    *,
    role: str,
    q: str = "",
    types: list[str] | None = None,
    severity_min: int | None = None,
    severity_max: int | None = None,
    tlp: list[str] | None = None,
    status: str | None = None,
    source: str | None = None,
    tag: str | None = None,
    attack: str | None = None,
    country: str | None = None,
    kev: bool | None = None,
    sort: str = "severity_desc",
    page: int = 1,
    size: int = 25,
) -> dict[str, Any]:
    clearance = allowed_tlps(role)
    if not clearance:
        return {"items": [], "total": 0, "page": page, "size": size, "facets": {}}
    query = select(Indicator)
    if q.strip():
        like = f"%{q.strip()[:100]}%"
        if settings.search_backend == "elasticsearch":
            try:
                from .indexing import indicator_index, search_ids

                rows = search_ids(indicator_index(), q)
                query = query.where(Indicator.id.in_(rows) if rows else false())
            except Exception:
                query = query.where(Indicator.value.ilike(like) | Indicator.notes.ilike(like))
        elif IS_SQLITE:
            fts = fts_query(q)
            try:
                rows = (
                    db.execute(
                        text(
                            "SELECT indicator_id FROM indicator_fts "
                            "WHERE indicator_fts MATCH :q LIMIT 5000"
                        ),
                        {"q": fts},
                    ).scalars().all()
                    if fts
                    else []
                )
                query = query.where(Indicator.id.in_(rows) if rows else false())
            except Exception:
                query = query.where(Indicator.value.ilike(like) | Indicator.notes.ilike(like))
        else:
            query = query.where(Indicator.value.ilike(like) | Indicator.notes.ilike(like))
    if types:
        query = query.where(Indicator.type.in_(types))
    if severity_min is not None:
        query = query.where(Indicator.severity_score >= severity_min)
    if severity_max is not None:
        query = query.where(Indicator.severity_score <= severity_max)
    allowed = [value for value in (tlp or list(clearance)) if value in clearance]
    query = query.where(Indicator.tlp.in_(allowed if allowed else list(clearance)))
    if status:
        query = query.where(Indicator.status == status)
    if country:
        query = query.where(Indicator.country == country.upper())
    if kev is not None:
        query = query.where(Indicator.kev.is_(kev))
    if source:
        source_ids = select(IndicatorSource.indicator_id).where(
            IndicatorSource.source_name.ilike(f"%{source}%")
        )
        query = query.where(Indicator.id.in_(source_ids))
    if tag:
        tag_ids = (
            select(IndicatorTag.indicator_id)
            .join(Tag, Tag.id == IndicatorTag.tag_id)
            .where(Tag.name == tag.lower())
        )
        query = query.where(Indicator.id.in_(tag_ids))
    if attack:
        attack_ids = select(IndicatorAttack.indicator_id).where(
            IndicatorAttack.technique_id == attack.upper()
        )
        query = query.where(Indicator.id.in_(attack_ids))

    sort_map = {
        "severity_desc": (Indicator.severity_score.desc(), Indicator.last_seen.desc()),
        "severity_asc": (Indicator.severity_score.asc(), Indicator.last_seen.desc()),
        "last_seen_desc": (Indicator.last_seen.desc(),),
        "first_seen_desc": (Indicator.first_seen.desc(),),
        "value_asc": (Indicator.value.asc(),),
    }
    query = query.order_by(*sort_map.get(sort, sort_map["severity_desc"]))
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    page = max(1, page)
    size = max(1, min(100, size))
    items = db.execute(query.offset((page - 1) * size).limit(size)).scalars().all()

    filtered_ids = select(query.order_by(None).subquery().c.id)
    facets = _facets(db, filtered_ids)
    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "facets": facets,
    }


def _facets(db: Session, filtered_ids) -> dict[str, Any]:
    types = db.execute(
        select(Indicator.type, func.count())
        .where(Indicator.id.in_(filtered_ids))
        .group_by(Indicator.type)
        .order_by(func.count().desc())
    ).all()
    tlps = db.execute(
        select(Indicator.tlp, func.count())
        .where(Indicator.id.in_(filtered_ids))
        .group_by(Indicator.tlp)
    ).all()
    statuses = db.execute(
        select(Indicator.status, func.count())
        .where(Indicator.id.in_(filtered_ids))
        .group_by(Indicator.status)
    ).all()
    sources = db.execute(
        select(IndicatorSource.source_name, func.count(func.distinct(IndicatorSource.indicator_id)))
        .where(IndicatorSource.indicator_id.in_(filtered_ids))
        .group_by(IndicatorSource.source_name)
        .order_by(func.count().desc())
        .limit(12)
    ).all()
    tags = db.execute(
        select(Tag.name, func.count(IndicatorTag.indicator_id))
        .join(IndicatorTag, IndicatorTag.tag_id == Tag.id)
        .where(IndicatorTag.indicator_id.in_(filtered_ids))
        .group_by(Tag.name)
        .order_by(func.count().desc())
        .limit(20)
    ).all()
    attacks = db.execute(
        select(IndicatorAttack.technique_id, func.count())
        .where(IndicatorAttack.indicator_id.in_(filtered_ids))
        .group_by(IndicatorAttack.technique_id)
        .order_by(func.count().desc())
        .limit(20)
    ).all()
    return {
        "types": [{"value": row[0], "count": row[1]} for row in types],
        "tlp": [{"value": row[0], "count": row[1]} for row in tlps],
        "status": [{"value": row[0], "count": row[1]} for row in statuses],
        "sources": [{"value": row[0], "count": row[1]} for row in sources],
        "tags": [{"value": row[0], "count": row[1]} for row in tags],
        "attack": [{"value": row[0], "count": row[1]} for row in attacks],
    }


def search_events(
    db: Session, *, q: str = "", event_type: str | None = None, page: int = 1, size: int = 25
) -> dict[str, Any]:
    query = select(SecurityEvent)
    if q.strip():
        like = f"%{q.strip()[:100]}%"
        if settings.search_backend == "elasticsearch":
            try:
                from .indexing import event_index, search_ids

                rows = search_ids(event_index(), q)
                query = query.where(SecurityEvent.id.in_(rows) if rows else false())
            except Exception:
                query = query.where(
                    SecurityEvent.src_ip.ilike(like)
                    | SecurityEvent.dst_ip.ilike(like)
                    | SecurityEvent.domain.ilike(like)
                    | SecurityEvent.file_hash.ilike(like)
                    | SecurityEvent.user_name.ilike(like)
                    | SecurityEvent.host.ilike(like)
                )
        else:
            query = query.where(
                SecurityEvent.src_ip.ilike(like)
                | SecurityEvent.dst_ip.ilike(like)
                | SecurityEvent.domain.ilike(like)
                | SecurityEvent.file_hash.ilike(like)
                | SecurityEvent.user_name.ilike(like)
                | SecurityEvent.host.ilike(like)
            )
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    rows = db.execute(
        query.order_by(SecurityEvent.event_time.desc())
        .offset((max(1, page) - 1) * size)
        .limit(min(100, max(1, size)))
    ).scalars().all()
    return {
        "items": [
            {
                "id": row.id,
                "event_time": iso(row.event_time),
                "event_type": row.event_type,
                "src_ip": row.src_ip,
                "dst_ip": row.dst_ip,
                "domain": row.domain,
                "file_hash": row.file_hash,
                "user_name": row.user_name,
                "host": row.host,
                "country": row.country,
                "raw": row.raw,
            }
            for row in rows
        ],
        "total": total,
        "page": page,
        "size": size,
    }

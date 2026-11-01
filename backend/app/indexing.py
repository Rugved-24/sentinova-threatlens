from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Indicator, IndicatorAttack, IndicatorSource, IndicatorTag, SecurityEvent, Tag

logger = logging.getLogger("threatlens.indexing")
settings = get_settings()

_client = None
_indices_ready = False


def _prefix() -> str:
    return (settings.elasticsearch_index_prefix or "threatlens").strip() or "threatlens"


def indicator_index() -> str:
    return f"{_prefix()}-indicators"


def event_index() -> str:
    return f"{_prefix()}-events"


def client():
    global _client
    if not settings.elasticsearch_url:
        return None
    if _client is None:
        from elasticsearch import Elasticsearch

        _client = Elasticsearch(
            settings.elasticsearch_url,
            request_timeout=10,
            retry_on_timeout=True,
            max_retries=2,
        )
    return _client


def ensure_indices() -> bool:
    global _indices_ready
    es = client()
    if es is None:
        return False
    if _indices_ready:
        return True
    mappings = {
        indicator_index(): {
            "mappings": {
                "properties": {
                    "indicator_id": {"type": "keyword"},
                    "value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "notes": {"type": "text"},
                    "tags": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "attack": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "type": {"type": "keyword"},
                    "tlp": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "severity": {"type": "integer"},
                    "country": {"type": "keyword"},
                    "source": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "kev": {"type": "boolean"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                }
            }
        },
        event_index(): {
            "mappings": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "domain": {"type": "keyword"},
                    "file_hash": {"type": "keyword"},
                    "user_name": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "country": {"type": "keyword"},
                    "raw": {"type": "object", "enabled": False},
                    "event_time": {"type": "date"},
                }
            }
        },
    }
    for name, body in mappings.items():
        try:
            if not es.indices.exists(index=name):
                es.indices.create(index=name, **body)
        except Exception:
            logger.exception("Could not create Elasticsearch index %s", name)
            return False
    _indices_ready = True
    return True


def _indicator_document(db: Session, indicator: Indicator) -> dict[str, Any]:
    tags = db.execute(
        select(Tag.name)
        .join(IndicatorTag, IndicatorTag.tag_id == Tag.id)
        .where(IndicatorTag.indicator_id == indicator.id)
    ).scalars().all()
    attack = db.execute(
        select(IndicatorAttack.technique_id).where(IndicatorAttack.indicator_id == indicator.id)
    ).scalars().all()
    sources = db.execute(
        select(IndicatorSource.source_name).where(IndicatorSource.indicator_id == indicator.id)
    ).scalars().all()
    return {
        "indicator_id": indicator.id,
        "value": indicator.value,
        "notes": indicator.notes or "",
        "tags": list(tags),
        "attack": list(attack),
        "type": indicator.type,
        "tlp": indicator.tlp,
        "status": indicator.status,
        "severity": indicator.severity_score,
        "country": indicator.country,
        "source": list(sources),
        "kev": indicator.kev,
        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
    }


def _event_document(event: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": event.id,
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "domain": event.domain,
        "file_hash": event.file_hash,
        "user_name": event.user_name,
        "host": event.host,
        "country": event.country,
        "raw": event.raw or {},
        "event_time": event.event_time.isoformat() if event.event_time else None,
    }


def index_indicator_by_id(db: Session, indicator_id: str) -> None:
    es = client()
    if es is None:
        return
    db.flush()
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        delete_indicator(indicator_id)
        return
    es.index(index=indicator_index(), id=indicator.id, document=_indicator_document(db, indicator))


def delete_indicator(indicator_id: str) -> None:
    es = client()
    if es is None:
        return
    try:
        es.delete(index=indicator_index(), id=indicator_id, ignore=[404])
    except Exception:
        logger.exception("Could not delete indicator %s from Elasticsearch", indicator_id)


def index_event_by_id(db: Session, event_id: str) -> None:
    es = client()
    if es is None:
        return
    event = db.get(SecurityEvent, event_id)
    if event is None:
        return
    es.index(index=event_index(), id=event.id, document=_event_document(event))


def _bulk_actions(db: Session, *, include_events: bool):
    for indicator in db.execute(select(Indicator)).scalars():
        yield {
            "_index": indicator_index(),
            "_id": indicator.id,
            "_source": _indicator_document(db, indicator),
        }
    if include_events:
        for event in db.execute(select(SecurityEvent)).scalars():
            yield {
                "_index": event_index(),
                "_id": event.id,
                "_source": _event_document(event),
            }


def rebuild_all(db: Session) -> int:
    es = client()
    if es is None or not ensure_indices():
        return 0
    from elasticsearch.helpers import bulk

    success, errors = bulk(
        es,
        _bulk_actions(db, include_events=True),
        chunk_size=500,
        request_timeout=60,
        raise_on_error=False,
    )
    if errors:
        logger.warning("Elasticsearch bulk projection reported %s failed documents", errors)
    return int(success)


def search_ids(index: str, query: str, *, limit: int = 5000) -> list[str]:
    es = client()
    if es is None or not query.strip():
        return []
    fields = (
        ["value^4", "notes", "tags^2", "attack^2", "source"]
        if index == indicator_index()
        else ["src_ip", "dst_ip", "domain", "file_hash", "user_name", "host", "event_type"]
    )
    body = {
        "size": limit,
        "_source": False,
        "query": {
            "multi_match": {
                "query": query[:200],
                "fields": fields,
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        },
    }
    response = es.search(index=index, **body)
    return [hit["_id"] for hit in response.get("hits", {}).get("hits", [])]

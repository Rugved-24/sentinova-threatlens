from __future__ import annotations

import hashlib
import hmac
import logging
import time
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from ..audit import record_audit
from ..config import get_settings
from ..correlation import correlate_indicator, create_alerts_for_indicator, indicators_for_events
from ..db import session_scope
from ..events import manager
from ..indexing import index_event_by_id
from ..ingest import upsert_indicator
from ..models import SecurityEvent
from ..normalize import canonicalize
from ..schemas import HookPayload
from ..security import client_ip, limiter
from ..transaction_guards import claim_webhook
from ..utils import utcnow

router = APIRouter(tags=["integrations"])
settings = get_settings()
logger = logging.getLogger("threatlens.hooks")


class WebhookActor:
    id = None
    email = "webhook@threatlens.local"


def _parse_time(value) -> datetime:
    if not value:
        return utcnow()
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).replace(tzinfo=None)
    except (ValueError, TypeError):
        return utcnow()


@router.post("/hooks/ingest")
async def ingest_hook(request: Request):
    if not settings.webhook_secret or len(settings.webhook_secret) < 32:
        raise HTTPException(
            status_code=503,
            detail={"error_code": "hook_disabled", "message": "Integration hook is not configured"},
        )
    ip = client_ip(request)
    allowed, retry_after = limiter.check(f"hook:{ip}", 60, 60)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={"error_code": "rate_limited", "message": "Too many webhook calls"},
            headers={"Retry-After": str(retry_after)},
        )
    body = await request.body()
    if len(body) > 1_000_000:
        raise HTTPException(
            status_code=413,
            detail={"error_code": "payload_too_large", "message": "Webhook payload exceeds 1 MB"},
        )
    timestamp = request.headers.get("x-threatlens-timestamp", "")
    signature = request.headers.get("x-threatlens-signature", "")
    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error_code": "invalid_signature", "message": "Missing timestamp"},
        ) from exc
    if abs(time.time() - sent_at) > 300:
        raise HTTPException(
            status_code=401,
            detail={"error_code": "stale_signature", "message": "Webhook timestamp outside replay window"},
        )
    expected = hmac.new(
        settings.webhook_secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    if not signature or not hmac.compare_digest(expected, signature):
        raise HTTPException(
            status_code=401,
            detail={"error_code": "invalid_signature", "message": "Webhook signature is invalid"},
        )
    try:
        payload = HookPayload.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_payload", "message": "Webhook payload is invalid"},
        ) from exc
    created = 0
    updated = 0
    alerts_created = 0
    events_created = 0
    with session_scope() as db:
        fingerprint = hashlib.sha256(timestamp.encode() + b"." + body).hexdigest()
        if not claim_webhook(db, fingerprint, sent_at):
            raise HTTPException(
                status_code=409,
                detail={"error_code": "webhook_replayed", "message": "This signed request was already processed"},
            )
        affected = {}
        incoming_events = []
        for item in payload.indicators[:200]:
            try:
                confidence = int(item.get("confidence", 60))
            except (TypeError, ValueError):
                confidence = 60
            indicator, was_created = upsert_indicator(
                db,
                value=str(item.get("value", "")),
                kind=item.get("type"),
                source=str(item.get("source", "Webhook integration"))[:120],
                confidence=max(0, min(100, confidence)),
                reliability=0.65,
                tlp=str(item.get("tlp", "amber")),
                tags=[str(tag)[:64] for tag in (item.get("tags") or [])[:20]],
                attack_ids=[str(tech)[:16] for tech in (item.get("attack_ids") or [])[:20]],
                notes=str(item.get("notes", ""))[:4000] or None,
                malicious_ratio=float(item.get("malicious_ratio", 0.5) or 0.5),
            )
            if indicator is None:
                continue
            created += 1 if was_created else 0
            updated += 0 if was_created else 1
            affected[indicator.id] = indicator
        for item in payload.events[:200]:
            src_ip = item.get("src_ip")
            dst_ip = item.get("dst_ip")
            domain = item.get("domain")
            file_hash = item.get("file_hash")
            src_valid = canonicalize(str(src_ip), "ip") if src_ip else None
            dst_valid = canonicalize(str(dst_ip), "ip") if dst_ip else None
            domain_valid = canonicalize(str(domain), "domain") if domain else None
            hash_valid = canonicalize(str(file_hash), "hash_sha256") if file_hash else None
            event = SecurityEvent(
                event_time=_parse_time(item.get("event_time")),
                event_type=str(item.get("event_type", "external"))[:48],
                src_ip=src_valid[0] if src_valid else None,
                dst_ip=dst_valid[0] if dst_valid else None,
                domain=domain_valid[0] if domain_valid else None,
                file_hash=hash_valid[0] if hash_valid else None,
                user_name=str(item.get("user_name", ""))[:120] or None,
                host=str(item.get("host", ""))[:120] or None,
                country=str(item.get("country", ""))[:64] or None,
                raw={"source": "webhook"},
            )
            db.add(event)
            incoming_events.append(event)
            events_created += 1
        db.flush()
        affected.update((item.id, item) for item in indicators_for_events(db, incoming_events))
        for indicator in affected.values():
            events = correlate_indicator(db, indicator)
            alerts_created += len(create_alerts_for_indicator(db, indicator, events))
        record_audit(
            db,
            "hook.ingest",
            actor=WebhookActor,
            object_type="webhook",
            detail={
                "indicators_created": created,
                "indicators_updated": updated,
                "events_created": events_created,
                "alerts_created": alerts_created,
                "source_ip": ip,
            },
        )
        db.commit()
        for event in incoming_events:
            try:
                index_event_by_id(db, event.id)
            except Exception:
                logger.exception("Event %s saved, but Elasticsearch indexing failed", event.id)
    if alerts_created:
        manager.publish(
            "alerts.stream",
            {"title": f"{alerts_created} new alert(s) from integration", "severity": "high"},
        )
    return {
        "data": {
            "indicators_created": created,
            "indicators_updated": updated,
            "events_created": events_created,
            "alerts_created": alerts_created,
        }
    }

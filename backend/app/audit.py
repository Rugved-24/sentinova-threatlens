from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .context import correlation_id
from .models import AuditLog
from .transaction_guards import lock_audit_chain
from .utils import canonical_json, iso, redact, sha256, utcnow


def record_audit(
    db: Session,
    action: str,
    *,
    actor=None,
    object_type: str | None = None,
    object_id: str | None = None,
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    actor_id = getattr(actor, "id", None)
    actor_email = getattr(actor, "email", None)
    ip = None
    user_agent = None
    if request is not None:
        forwarded = request.headers.get("x-forwarded-for", "")
        ip = (
            forwarded.split(",")[0].strip()[:64]
            if forwarded
            else (request.client.host if request.client else None)
        )
        user_agent = request.headers.get("user-agent", "")[:255] or None

    lock_audit_chain(db)
    db.flush()
    previous = db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()
    prev_hash = previous.entry_hash if previous else ""
    ts = utcnow()
    safe_detail = redact(detail or {})
    body = {
        "ts": iso(ts),
        "actor_id": actor_id,
        "actor_email": actor_email,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "ip": ip,
        "correlation_id": correlation_id.get(),
        "detail": safe_detail,
    }
    entry_hash = sha256(prev_hash + canonical_json(body))
    entry = AuditLog(
        ts=ts,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip=ip,
        user_agent=user_agent,
        correlation_id=correlation_id.get(),
        detail=safe_detail,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.flush()
    return entry


def verify_audit_chain(db: Session) -> dict[str, Any]:
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    previous_hash = ""
    for row in rows:
        body = {
            "ts": iso(row.ts),
            "actor_id": row.actor_id,
            "actor_email": row.actor_email,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "ip": row.ip,
            "correlation_id": row.correlation_id,
            "detail": row.detail or {},
        }
        expected = sha256(previous_hash + canonical_json(body))
        if row.prev_hash != previous_hash or row.entry_hash != expected:
            return {
                "valid": False,
                "entries": len(rows),
                "broken_at": row.id,
                "message": "Audit chain integrity check failed",
            }
        previous_hash = row.entry_hash
    return {
        "valid": True,
        "entries": len(rows),
        "head": previous_hash,
        "message": "Audit chain verified",
    }

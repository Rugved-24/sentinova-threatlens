"""Database-backed guards whose writes commit or roll back with the caller."""

from datetime import UTC, datetime

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .models import AuditChainLock, WebhookReceipt
from .utils import utcnow


def _insert(db, model):
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        return pg_insert(model)
    if dialect == "sqlite":
        return sqlite_insert(model)
    raise ValueError(f"Unsupported database for transaction guards: {dialect}")


def lock_audit_chain(db):
    # Updating this singleton holds a database write lock until commit/rollback.
    db.execute(_insert(db, AuditChainLock).values(id=1).on_conflict_do_update(
        index_elements=["id"], set_={"id": 1},
    ))


def claim_webhook(db, fingerprint, sent_at):
    # Keep future-dated signatures for their entire acceptance window too.
    expires_at = datetime.fromtimestamp(sent_at + 301, UTC).replace(tzinfo=None)
    db.execute(delete(WebhookReceipt).where(WebhookReceipt.expires_at < utcnow()))
    claimed = db.scalar(_insert(db, WebhookReceipt).values(
        id=fingerprint, expires_at=expires_at,
    ).on_conflict_do_nothing(index_elements=["id"]).returning(WebhookReceipt.id))
    return claimed is not None

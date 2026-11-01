import hashlib
import hmac
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.audit import record_audit, verify_audit_chain
from app.models import AuditChainLock, AuditLog, SecurityEvent, WebhookReceipt
from app.routers import hooks
from app.transaction_guards import claim_webhook
from app.utils import utcnow
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

TEST_DATABASES = ["sqlite"] + (["postgresql"] if os.getenv("THREATLENS_TEST_POSTGRES_URL") else [])


@pytest.fixture(params=TEST_DATABASES)
def isolated_sessions(tmp_path, request):
    admin = None
    if request.param == "postgresql":
        url = os.environ["THREATLENS_TEST_POSTGRES_URL"]
        schema = "test_guards_" + uuid4().hex
        admin = create_engine(url)
        with admin.begin() as connection:
            connection.execute(CreateSchema(schema))
        engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    else:
        engine = create_engine(f"sqlite:///{(tmp_path / 'guards.db').as_posix()}", connect_args={"timeout": 15})
    try:
        for model in (AuditLog, AuditChainLock, WebhookReceipt):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    finally:
        engine.dispose()
        if admin:
            with admin.begin() as connection:
                connection.execute(DropSchema(schema, cascade=True))
            admin.dispose()


def signed_request(domain, timestamp=None):
    body = json.dumps({"events": [{"domain": domain}]}).encode()
    stamp = str(timestamp if timestamp is not None else int(time.time()))
    signature = hmac.new(
        hooks.settings.webhook_secret.encode(), stamp.encode() + b"." + body, hashlib.sha256,
    ).hexdigest()
    return {"content": body, "headers": {
        "content-type": "application/json", "x-threatlens-timestamp": stamp,
        "x-threatlens-signature": signature,
    }}


def test_exact_webhook_replay_is_rejected_without_duplicate_events_or_audit(client, db):
    domain = f"{uuid4().hex}.example"
    request = signed_request(domain)
    first = client.post("/api/v1/hooks/ingest", **request)
    assert first.status_code == 200, first.text
    before = db.scalar(select(func.count()).select_from(AuditLog))
    replay = client.post("/api/v1/hooks/ingest", **request)
    assert replay.status_code == 409, replay.text
    assert replay.json()["error_code"] == "webhook_replayed"
    assert db.scalar(select(func.count()).select_from(AuditLog)) == before
    assert db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.domain == domain)) == 1


def test_failed_ingestion_rolls_back_receipt_and_can_be_retried(client, db, monkeypatch):
    domain = f"{uuid4().hex}.example"
    request = signed_request(domain)
    original = hooks.record_audit

    def fail(*args, **kwargs):
        raise RuntimeError("Simulated transaction failure")

    monkeypatch.setattr(hooks, "record_audit", fail)
    with pytest.raises(RuntimeError, match="Simulated transaction failure"):
        client.post("/api/v1/hooks/ingest", **request)
    assert db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.domain == domain)) == 0
    monkeypatch.setattr(hooks, "record_audit", original)
    response = client.post("/api/v1/hooks/ingest", **request)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("offset", [-601, 601])
def test_out_of_window_signature_creates_no_receipt(client, db, offset):
    before = db.scalar(select(func.count()).select_from(WebhookReceipt))
    response = client.post("/api/v1/hooks/ingest", **signed_request(
        f"{uuid4().hex}.example", int(time.time()) + offset,
    ))
    assert response.status_code == 401
    assert db.scalar(select(func.count()).select_from(WebhookReceipt)) == before


def test_receipt_survives_new_session_and_keeps_future_signature_window(isolated_sessions):
    sent_at = int(time.time()) + 250
    with isolated_sessions.begin() as db:
        assert claim_webhook(db, "a" * 64, sent_at)
    with isolated_sessions.begin() as db:
        assert not claim_webhook(db, "a" * 64, sent_at)
        receipt = db.get(WebhookReceipt, "a" * 64)
        assert receipt.expires_at == datetime.fromtimestamp(sent_at + 301, UTC).replace(tzinfo=None)


def test_expired_receipts_are_pruned(isolated_sessions):
    with isolated_sessions.begin() as db:
        db.add(WebhookReceipt(id="b" * 64, expires_at=utcnow() - timedelta(seconds=1)))
    with isolated_sessions.begin() as db:
        assert claim_webhook(db, "c" * 64, int(time.time()))
        assert db.get(WebhookReceipt, "b" * 64) is None


def test_concurrent_receipt_claims_have_one_winner(isolated_sessions):
    stamp = int(time.time())

    def claim(_):
        with isolated_sessions.begin() as db:
            return claim_webhook(db, "d" * 64, stamp)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(claim, range(8))) == 1


def test_multiple_audit_entries_in_one_transaction_form_a_chain(isolated_sessions):
    with isolated_sessions.begin() as db:
        first = record_audit(db, "batch.first")
        second = record_audit(db, "batch.second")
        assert second.prev_hash == first.entry_hash
    with isolated_sessions() as db:
        result = verify_audit_chain(db)
        assert result["valid"]
        assert result["entries"] == 2


def test_rolled_back_audit_entry_does_not_become_chain_head(isolated_sessions):
    with isolated_sessions.begin() as db:
        first = record_audit(db, "committed.first")
    with isolated_sessions() as db:
        record_audit(db, "rolled_back")
        db.rollback()
    with isolated_sessions.begin() as db:
        last = record_audit(db, "committed.last")
        assert last.prev_hash == first.entry_hash
    with isolated_sessions() as db:
        result = verify_audit_chain(db)
        assert result["valid"]
        assert result["entries"] == 2


def test_concurrent_audit_writers_keep_one_chain(isolated_sessions):
    def write(worker):
        for batch in range(4):
            with isolated_sessions.begin() as db:
                for entry in range(2):
                    record_audit(db, "concurrent", detail={"worker": worker, "batch": batch, "entry": entry})

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(4)))
    with isolated_sessions() as db:
        result = verify_audit_chain(db)
        assert result["valid"], result
        assert result["entries"] == 32

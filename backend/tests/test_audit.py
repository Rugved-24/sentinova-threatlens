from __future__ import annotations

import pytest
from app.audit import record_audit, verify_audit_chain
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError


def test_chain_verifies(db):
    record_audit(db, "test.chain", object_type="test", detail={"value": 1})
    db.commit()
    result = verify_audit_chain(db)
    assert result["valid"] is True
    assert result["entries"] >= 1


def test_chain_detects_tampering(db):
    entry = record_audit(db, "test.tamper", detail={"safe": True})
    db.commit()
    entry_id = entry.id
    with pytest.raises(IntegrityError):
        db.execute(
            text("UPDATE audit_log SET action = 'tampered' WHERE id = :id"),
            {"id": entry_id},
        )
        db.commit()
    db.rollback()


def test_audit_redacts_secrets(db):
    entry = record_audit(
        db,
        "test.redaction",
        detail={"password": "plain-text", "nested": {"api_key": "secret"}, "safe": "visible"},
    )
    db.commit()
    assert entry.detail["password"] == "[REDACTED]"
    assert entry.detail["nested"]["api_key"] == "[REDACTED]"
    assert entry.detail["safe"] == "visible"

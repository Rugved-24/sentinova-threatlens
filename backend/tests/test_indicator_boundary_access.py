from uuid import uuid4

import pytest
from app.models import AuditLog, Indicator, IndicatorRelationship, IndicatorSource, IndicatorTag
from app.routers import indicators
from sqlalchemy import func, select


def linked_pair(db, direction="out"):
    visible = Indicator(value=f"visible-{uuid4().hex}.example", type="domain", tlp="amber")
    hidden = Indicator(value=f"hidden-{uuid4().hex}.example", type="domain", tlp="red", notes="Restricted evidence")
    db.add_all([visible, hidden])
    db.flush()
    source, target = (visible, hidden) if direction == "out" else (hidden, visible)
    edge = IndicatorRelationship(source_id=source.id, target_id=target.id, relation_type="related-to", confidence=60)
    db.add(edge)
    db.commit()
    return visible, hidden, edge


def counts(db, indicator_id):
    return tuple(db.scalar(select(func.count()).select_from(model).where(condition)) for model, condition in (
        (IndicatorSource, IndicatorSource.indicator_id == indicator_id),
        (IndicatorTag, IndicatorTag.indicator_id == indicator_id),
        (AuditLog, AuditLog.object_id == indicator_id),
    ))


@pytest.mark.parametrize("role", ["analyst", "hunter", "executive"])
def test_duplicate_submission_cannot_read_or_modify_restricted_indicator(client, headers, db, role, monkeypatch):
    _, hidden, _ = linked_pair(db)
    before = counts(db, hidden.id)
    before_seen = hidden.last_seen

    def forbidden_correlation(*args, **kwargs):
        raise AssertionError("Restricted submission reached correlation")

    monkeypatch.setattr(indicators, "correlate_indicator", forbidden_correlation)
    response = client.post("/api/v1/indicators", headers=headers(role), json={
        "value": hidden.value.upper() + ".", "type": "domain", "tlp": "amber",
        "notes": "Unauthorized note", "tags": ["unauthorized"],
    })
    assert response.status_code == 403, response.text
    assert hidden.value not in response.text
    db.refresh(hidden)
    assert hidden.notes == "Restricted evidence"
    assert hidden.last_seen == before_seen
    assert hidden.tlp == "red"
    assert counts(db, hidden.id) == before


@pytest.mark.parametrize("role", ["admin", "engineer", "responder"])
def test_cleared_user_can_submit_existing_restricted_indicator(client, headers, db, role):
    _, hidden, _ = linked_pair(db)
    response = client.post("/api/v1/indicators", headers=headers(role), json={
        "value": hidden.value, "type": "domain", "tlp": "amber", "notes": "Authorized note",
    })
    assert response.status_code == 201, response.text
    assert response.json()["meta"]["created"] is False
    assert response.json()["data"]["tlp"] == "red"
    db.refresh(hidden)
    assert "Authorized note" in hidden.notes


@pytest.mark.parametrize("direction", ["in", "out"])
@pytest.mark.parametrize("role", ["admin", "engineer", "responder", "analyst", "hunter", "executive"])
def test_relationship_detail_respects_each_role(client, headers, db, role, direction):
    visible, hidden, edge = linked_pair(db, direction)
    response = client.get(f"/api/v1/indicators/{visible.id}", headers=headers(role))
    if role == "executive":
        assert response.status_code == 403
        return
    assert response.status_code == 200, response.text
    relationships = response.json()["data"]["relationships"]
    if role in {"analyst", "hunter"}:
        assert relationships == []
        assert hidden.value not in response.text
        assert hidden.id not in response.text
        assert edge.id not in response.text
    else:
        assert relationships[0]["other"]["id"] == hidden.id
        assert relationships[0]["direction"] == direction


@pytest.mark.parametrize("action", ["update", "enrich", "lookup", "submit", "relationship"])
def test_other_detail_responses_do_not_leak_related_indicators(client, headers, db, action, monkeypatch):
    visible, hidden, _ = linked_pair(db)
    monkeypatch.setattr(indicators, "enrich_indicator", lambda *args, **kwargs: {})
    endpoint = f"/api/v1/indicators/{visible.id}"
    auth = headers("analyst")
    if action == "update":
        response = client.patch(endpoint, headers=auth, json={"notes": "Triage"})
    elif action == "enrich":
        response = client.post(endpoint + "/enrich", headers=auth)
    elif action == "lookup":
        response = client.get(f"/api/v1/domains/{visible.value}/analysis", headers=auth)
    elif action == "submit":
        response = client.post("/api/v1/indicators", headers=auth, json={"value": visible.value, "type": "domain"})
    else:
        response = client.post(endpoint + "/relationships", headers=auth, json={
            "target_value": f"{uuid4().hex}.example", "target_type": "domain", "relation_type": "related-to",
        })
    assert response.status_code in {200, 201}, response.text
    assert hidden.value not in response.text
    assert hidden.id not in response.text


def test_relationship_creation_cannot_modify_restricted_target(client, headers, db):
    visible, hidden, _ = linked_pair(db)
    before = counts(db, hidden.id)
    before_seen = hidden.last_seen
    response = client.post(f"/api/v1/indicators/{visible.id}/relationships", headers=headers("analyst"), json={
        "target_value": hidden.value.upper() + ".", "target_type": "domain", "relation_type": "resolves-to",
    })
    assert response.status_code == 403, response.text
    db.refresh(hidden)
    assert hidden.last_seen == before_seen
    assert counts(db, hidden.id) == before
    assert db.scalar(select(IndicatorRelationship.id).where(
        IndicatorRelationship.source_id == visible.id, IndicatorRelationship.target_id == hidden.id,
        IndicatorRelationship.relation_type == "resolves-to",
    )) is None


def test_authorized_relationship_creation_remains_available(client, headers, db):
    visible, hidden, _ = linked_pair(db)
    response = client.post(f"/api/v1/indicators/{visible.id}/relationships", headers=headers("admin"), json={
        "target_value": hidden.value, "target_type": "domain", "relation_type": "resolves-to",
    })
    assert response.status_code == 201, response.text
    assert any(row["other"]["id"] == hidden.id and row["relation_type"] == "resolves-to"
               for row in response.json()["data"]["relationships"])

import hashlib
import hmac
import json
import time
from datetime import timedelta
from uuid import uuid4

import pytest
from app.db import SessionLocal
from app.models import Alert, AlertRule, AuditLog, Indicator, SecurityEvent
from app.routers import hooks
from app.utils import utcnow
from sqlalchemy import select


def new_indicator(client, headers, **extra):
    payload = {"value": f"{uuid4().hex}.example", "type": "domain", "tlp": "amber", **extra}
    response = client.post("/api/v1/indicators", headers=headers(), json=payload)
    assert response.status_code == 201, response.text
    return response.json()["data"]


def signed_hook(client, payload):
    body = json.dumps(payload).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        hooks.settings.webhook_secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256,
    ).hexdigest()
    return client.post("/api/v1/hooks/ingest", content=body, headers={
        "content-type": "application/json",
        "x-threatlens-timestamp": timestamp,
        "x-threatlens-signature": signature,
    })


def test_tag_only_edits_persist_and_refresh_search_and_audit(client, headers, db):
    item = new_indicator(client, headers)
    tag = "triage" + uuid4().hex
    endpoint = f"/api/v1/indicators/{item['id']}"
    for operation, expected in (("add_tags", [tag]), ("remove_tags", [])):
        response = client.patch(endpoint, headers=headers(), json={operation: [f"  {tag.upper()}  ", tag]})
        assert response.status_code == 200, response.text
        fresh = client.get(endpoint, headers=headers()).json()["data"]
        assert [entry["name"] for entry in fresh["tags"]] == expected
        search = client.get("/api/v1/indicators", headers=headers(), params={"q": tag}).json()["data"]
        assert (item["id"] in {row["id"] for row in search}) == bool(expected)
        audit = db.scalar(select(AuditLog).where(
            AuditLog.object_id == item["id"], AuditLog.action == "indicator.update",
        ).order_by(AuditLog.id.desc()))
        key = "added" if operation == "add_tags" else "removed"
        assert audit.detail["changes"]["tags"][key] == [tag]


def test_same_tag_added_and_removed_in_one_edit_stays_removed(client, headers):
    item = new_indicator(client, headers)
    endpoint = f"/api/v1/indicators/{item['id']}"
    response = client.patch(endpoint, headers=headers(), json={
        "add_tags": ["work   item"], "remove_tags": ["  WORK ITEM  "],
    })
    assert response.status_code == 200, response.text
    assert client.get(endpoint, headers=headers()).json()["data"]["tags"] == []


def test_attack_ids_can_be_cleared_without_other_edits(client, headers):
    item = new_indicator(client, headers, attack_ids=["T1059"])
    assert item["attack_ids"] == ["T1059"]
    endpoint = f"/api/v1/indicators/{item['id']}"
    response = client.patch(endpoint, headers=headers(), json={"attack_ids": []})
    assert response.status_code == 200, response.text
    assert client.get(endpoint, headers=headers()).json()["data"]["attack_ids"] == []


@pytest.mark.parametrize(("kind", "field"), [
    ("ip", "src_ip"), ("ip", "dst_ip"), ("domain", "domain"),
    ("hash_sha256", "file_hash"), ("url", "domain"),
])
def test_event_only_hook_correlates_existing_indicators(client, db, kind, field):
    host = f"{uuid4().hex}.example"
    value = {"ip": "2001:db8:a" + uuid4().hex[:3] + "::1", "domain": host,
             "hash_sha256": uuid4().hex * 2, "url": f"https://{host}:8443/path"}[kind]
    item = Indicator(value=value, type=kind, tlp="amber", status="active", last_seen=utcnow(), malicious_ratio=1)
    rule = AlertRule(name=uuid4().hex, min_score=40, enabled=True, tlp_max="red", route_roles=["admin"])
    unrelated = Indicator(value=f"unmatched-{uuid4().hex}.example", type="domain", internal_sightings=0)
    db.add_all([item, rule, unrelated])
    db.commit()
    response = signed_hook(client, {"events": [{field: host if kind == "url" else value}]})
    assert response.status_code == 200, response.text
    assert response.json()["data"]["events_created"] == 1
    assert response.json()["data"]["alerts_created"] >= 1
    db.refresh(item)
    db.refresh(unrelated)
    assert item.internal_sightings == 1
    assert unrelated.internal_sightings == 0
    alert = db.scalar(select(Alert).where(Alert.indicator_id == item.id, Alert.rule_id == rule.id))
    assert alert is not None
    assert "1 internal sighting(s)" in alert.description


def test_combined_hook_correlates_new_indicator_with_new_event(client, db):
    value = f"{uuid4().hex}.example"
    response = signed_hook(client, {
        "indicators": [{"value": value, "type": "domain"}], "events": [{"domain": value}],
    })
    assert response.status_code == 200, response.text
    item = db.scalar(select(Indicator).where(Indicator.value == value))
    assert item.internal_sightings == 1


def test_old_events_do_not_count_as_current_sightings(client, db):
    value = f"{uuid4().hex}.example"
    item = Indicator(value=value, type="domain", tlp="amber", last_seen=utcnow())
    db.add(item)
    db.commit()
    response = signed_hook(client, {"events": [{
        "domain": value, "event_time": (utcnow() - timedelta(days=100)).isoformat(),
    }]})
    assert response.status_code == 200, response.text
    db.refresh(item)
    assert item.internal_sightings == 0


def test_url_path_domain_does_not_count_as_hostname_match(client, db):
    domain = f"{uuid4().hex}.example"
    item = Indicator(value=f"https://other.example/{domain}", type="url", internal_sightings=7)
    db.add(item)
    db.commit()
    response = signed_hook(client, {"events": [{"domain": domain}]})
    assert response.status_code == 200, response.text
    db.refresh(item)
    assert item.internal_sightings == 7


@pytest.mark.parametrize("index_fails", [False, True])
def test_events_are_indexed_after_commit_and_survive_index_failure(client, monkeypatch, index_fails):
    indexed = []

    def index_event(_db, event_id):
        with SessionLocal() as reader:
            assert reader.get(SecurityEvent, event_id) is not None
        indexed.append(event_id)
        if index_fails:
            raise RuntimeError("Elasticsearch is offline")

    monkeypatch.setattr(hooks, "index_event_by_id", index_event)
    response = signed_hook(client, {"events": [{"domain": f"{uuid4().hex}.example"}]})
    assert response.status_code == 200, response.text
    assert len(indexed) == 1
    with SessionLocal() as reader:
        assert reader.get(SecurityEvent, indexed[0]) is not None

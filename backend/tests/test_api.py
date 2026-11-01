from __future__ import annotations

import hashlib
import hmac
import json
import time

from conftest import PASSWORD


def test_login_and_me(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@threatlens.io", "password": PASSWORD},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "admin"
    assert response.cookies.get("tl_refresh")
    me = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["data"]["email"] == "admin@threatlens.io"


def test_bad_login_is_generic(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@threatlens.io", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.json()["message"] == "Invalid email or password"


def test_rbac_and_tlp(client, headers):
    exec_headers = headers("executive")
    assert client.get("/api/v1/indicators", headers=exec_headers).status_code == 403
    assert client.get("/api/v1/users", headers=exec_headers).status_code == 403
    assert client.get("/api/v1/dashboards/executive", headers=exec_headers).status_code == 200

    created = client.post(
        "/api/v1/indicators",
        headers=headers("admin"),
        json={
            "value": "203.0.113.201",
            "type": "ip",
            "tlp": "red",
            "tags": ["test", "red"],
            "attack_ids": ["T1071"],
            "notes": "Red clearance test indicator",
            "confidence": 90,
        },
    )
    assert created.status_code == 201, created.text
    value = created.json()["data"]["value"]
    analyst = client.get(
        "/api/v1/indicators",
        headers=headers("analyst"),
        params={"q": value},
    )
    assert analyst.status_code == 200
    assert all(item["value"] != value for item in analyst.json()["data"])


def test_meta_is_available_to_every_role(client, headers):
    for role in ("admin", "engineer", "responder", "hunter", "analyst", "executive"):
        response = client.get("/api/v1/meta", headers=headers(role))
        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["feeds_total"] >= data["feeds_enabled"] >= 1
        assert data["attack_techniques"] >= 1
        assert data["version"]


def test_indicator_lifecycle(client, headers):
    created = client.post(
        "/api/v1/indicators",
        headers=headers("admin"),
        json={
            "value": "https://phish-check.example.org/login",
            "tlp": "amber",
            "tags": ["phishing"],
            "attack_ids": ["T1566"],
            "notes": "Lifecycle test",
            "confidence": 80,
        },
    )
    assert created.status_code == 201, created.text
    indicator = created.json()["data"]
    indicator_id = indicator["id"]
    assert indicator["type"] == "url"
    assert "score_breakdown" in indicator

    updated = client.patch(
        f"/api/v1/indicators/{indicator_id}",
        headers=headers("admin"),
        json={"notes": "Updated note", "add_tags": ["triage"], "tlp": "green"},
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["notes"] == "Updated note"
    assert "triage" in [tag["name"] for tag in updated.json()["data"]["tags"]]

    related = client.post(
        f"/api/v1/indicators/{indicator_id}/relationships",
        headers=headers("admin"),
        json={
            "target_value": "198.51.100.201",
            "target_type": "ip",
            "relation_type": "resolves-to",
        },
    )
    assert related.status_code == 201, related.text
    graph = client.get(
        f"/api/v1/indicators/{indicator_id}/graph",
        headers=headers("admin"),
        params={"depth": 2},
    )
    assert graph.status_code == 200
    assert graph.json()["data"]["nodes"]


def test_search_and_facets(client, headers):
    response = client.get(
        "/api/v1/search",
        headers=headers("hunter"),
        params={"q": "example", "facets": "true", "limit": 10},
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["data"], list)
    assert "facets" in body["meta"]
    assert body["meta"]["total"] >= 1


def test_alert_rules_and_incident_workflow(client, headers):
    rule = client.post(
        "/api/v1/alert-rules",
        headers=headers("admin"),
        json={
            "name": "Test rule",
            "min_score": 50,
            "types": ["ip"],
            "route_roles": ["analyst"],
        },
    )
    assert rule.status_code in {200, 201}, rule.text
    rule_id = rule.json()["data"]["id"]
    patched = client.patch(
        f"/api/v1/alert-rules/{rule_id}",
        headers=headers("admin"),
        json={"enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["data"]["enabled"] is False

    incident = client.post(
        "/api/v1/incidents",
        headers=headers("responder"),
        json={
            "title": "API test incident",
            "summary": "Created by the automated test suite.",
            "severity": "high",
            "status": "investigating",
        },
    )
    assert incident.status_code == 201, incident.text
    incident_id = incident.json()["data"]["id"]
    timeline = client.post(
        f"/api/v1/incidents/{incident_id}/timeline",
        headers=headers("responder"),
        json={"event_type": "note", "message": "Test timeline entry"},
    )
    assert timeline.status_code == 201
    detail = client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=headers("responder"),
    )
    assert detail.status_code == 200
    assert detail.json()["data"]["timeline"][-1]["message"] == "Test timeline entry"


def test_exports_reports_and_audit(client, headers):
    stix = client.get(
        "/api/v1/export/stix",
        headers=headers("admin"),
        params={"severity_min": 50},
    )
    assert stix.status_code == 200
    assert stix.headers["content-type"].startswith("application/stix+json")
    bundle = stix.json()
    assert bundle["type"] == "bundle"
    assert isinstance(bundle["objects"], list)

    csv = client.get(
        "/api/v1/export/csv",
        headers=headers("admin"),
        params={"severity_min": 50},
    )
    assert csv.status_code == 200
    assert csv.text.lstrip("\ufeff").startswith('"value","type"')

    report = client.post(
        "/api/v1/reports",
        headers=headers("admin"),
        json={"title": "Automated Test Report", "kind": "executive"},
    )
    assert report.status_code == 201, report.text
    report_id = report.json()["data"]["id"]
    download = client.get(
        f"/api/v1/reports/{report_id}/download",
        headers=headers("admin"),
    )
    assert download.status_code == 200
    assert download.content.startswith(b"%PDF")

    verified = client.get("/api/v1/audit/verify", headers=headers("admin"))
    assert verified.status_code == 200
    assert verified.json()["data"]["valid"] is True


def test_webhook_signature_and_ingest(client):
    body = json.dumps(
        {
            "indicators": [
                {
                    "value": "198.51.100.202",
                    "type": "ip",
                    "source": "SIEM webhook",
                    "tlp": "amber",
                    "confidence": 90,
                }
            ],
            "events": [],
        }
    ).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        b"test-webhook-secret-that-is-long-enough-2026",
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    response = client.post(
        "/api/v1/hooks/ingest",
        content=body,
        headers={
            "content-type": "application/json",
            "x-threatlens-timestamp": timestamp,
            "x-threatlens-signature": signature,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["indicators_created"] + response.json()["data"]["indicators_updated"] == 1

    bad = client.post(
        "/api/v1/hooks/ingest",
        content=body,
        headers={
            "content-type": "application/json",
            "x-threatlens-timestamp": timestamp,
            "x-threatlens-signature": "0" * 64,
        },
    )
    assert bad.status_code == 401


def test_security_headers_and_correlation_id(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"]
    assert response.headers["x-request-id"]
    assert response.headers["cache-control"] == "no-store"

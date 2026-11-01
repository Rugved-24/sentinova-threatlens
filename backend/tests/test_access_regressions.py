from __future__ import annotations

import pytest
from app.models import Indicator, Report, User
from app.routers import indicators
from sqlalchemy import select

CASES = [
    ("ip", "198.51.100.214", "/api/v1/reputation/ip/198.51.100.214"),
    ("domain", "restricted-review.example", "/api/v1/domains/restricted-review.example/analysis"),
    ("hash_sha256", "b9" * 32, "/api/v1/hash/" + "b9" * 32),
]


def restricted_indicator(db, kind, value):
    item = db.scalar(select(Indicator).where(Indicator.type == kind, Indicator.value == value))
    if item is None:
        item = Indicator(type=kind, value=value, tlp="red", notes="Restricted test evidence")
        db.add(item)
        db.commit()
    return item


@pytest.mark.parametrize(("kind", "value", "endpoint"), CASES)
def test_lookup_rejects_restricted_indicator(client, headers, db, monkeypatch, kind, value, endpoint):
    item = restricted_indicator(db, kind, value)

    def forbidden_enrichment(*args, **kwargs):
        raise AssertionError("Authorization must run before enrichment")

    monkeypatch.setattr(indicators, "enrich_indicator", forbidden_enrichment)
    for role in ("analyst", "hunter"):
        direct = client.get(f"/api/v1/indicators/{item.id}", headers=headers(role))
        lookup = client.get(endpoint, headers=headers(role))
        assert direct.status_code == 403
        assert lookup.status_code == 403, lookup.text
        assert value not in lookup.text


@pytest.mark.parametrize(("kind", "value", "endpoint"), CASES)
def test_authorized_lookup_still_works(client, headers, db, monkeypatch, kind, value, endpoint):
    restricted_indicator(db, kind, value)
    monkeypatch.setattr(indicators, "enrich_indicator", lambda *args, **kwargs: {})
    response = client.get(endpoint, headers=headers("admin"))
    assert response.status_code == 200, response.text
    assert response.json()["data"]["indicator"]["value"] == value


def new_incident(client, headers):
    response = client.post(
        "/api/v1/incidents", headers=headers("admin"),
        json={"title": "Report permission regression", "summary": "Restricted incident evidence"},
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


def test_executive_cannot_create_incident_report(client, headers):
    incident_id = new_incident(client, headers)
    response = client.post(
        "/api/v1/reports", headers=headers("executive"),
        json={"title": "Blocked report", "kind": "incident", "incident_id": incident_id},
    )
    assert response.status_code == 403, response.text


def test_executive_cannot_access_legacy_incident_report(client, headers, db):
    executive = db.scalar(select(User).where(User.role == "executive"))
    report = Report(
        title="Legacy incident report", kind="incident", requested_by=executive.id,
        status="completed", storage_path="unused-test-report.pdf",
    )
    db.add(report)
    db.commit()
    response = client.get(f"/api/v1/reports/{report.id}/download", headers=headers("executive"))
    assert response.status_code == 403, response.text
    listing = client.get("/api/v1/reports", headers=headers("executive"))
    assert listing.status_code == 200
    assert all(row["id"] != report.id for row in listing.json()["data"])


def test_admin_can_generate_incident_report(client, headers):
    incident_id = new_incident(client, headers)
    response = client.post(
        "/api/v1/reports", headers=headers("admin"),
        json={"title": "Permitted incident report", "kind": "incident", "incident_id": incident_id},
    )
    assert response.status_code == 201, response.text
    download = client.get(
        f"/api/v1/reports/{response.json()['data']['id']}/download", headers=headers("admin"),
    )
    assert download.status_code == 200
    assert download.content.startswith(b"%PDF")


def test_executive_can_generate_aggregate_report(client, headers):
    response = client.post(
        "/api/v1/reports", headers=headers("executive"),
        json={"title": "Permitted executive report", "kind": "executive"},
    )
    assert response.status_code == 201, response.text

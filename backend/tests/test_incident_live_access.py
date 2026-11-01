from __future__ import annotations

import asyncio
import time
import uuid

import pytest
from app.events import ConnectionManager
from app.models import Alert, Incident, IncidentTimeline, Indicator, Report, User
from sqlalchemy import select


def user_for(db, role):
    return db.scalar(select(User).where(User.role == role))


def restricted_case(db, link="alert"):
    indicator = Indicator(type="domain", value=f"{uuid.uuid4().hex}.example", tlp="red")
    incident = Incident(title="Restricted case", summary="Restricted case details")
    db.add_all([indicator, incident])
    db.flush()
    if link == "alert":
        db.add(Alert(
            title="Restricted alert", description="Secret evidence", severity="high", score=90,
            indicator_id=indicator.id, incident_id=incident.id, tlp="amber",
        ))
    else:
        db.add(IncidentTimeline(
            incident_id=incident.id, indicator_id=indicator.id, event_type="note", message="Secret evidence",
        ))
    db.commit()
    return incident, indicator


@pytest.mark.parametrize("link", ["alert", "timeline"])
@pytest.mark.parametrize("role", ["analyst", "hunter"])
def test_restricted_case_is_hidden_everywhere(client, headers, db, link, role):
    incident, _ = restricted_case(db, link)
    auth = headers(role)
    detail = client.get(f"/api/v1/incidents/{incident.id}", headers=auth)
    timeline = client.get(f"/api/v1/incidents/{incident.id}/timeline", headers=auth)
    assert detail.status_code == timeline.status_code == 403
    listing = client.get("/api/v1/incidents", headers=auth)
    assert listing.status_code == 200
    assert all(item["id"] != incident.id for item in listing.json()["data"])
    report = client.post(
        "/api/v1/reports", headers=auth,
        json={"title": "Blocked restricted report", "kind": "incident", "incident_id": incident.id},
    )
    assert report.status_code == 403, report.text


@pytest.mark.parametrize("link", ["alert", "timeline"])
def test_admin_can_read_restricted_case(client, headers, db, link):
    incident, _ = restricted_case(db, link)
    response = client.get(f"/api/v1/incidents/{incident.id}", headers=headers("admin"))
    assert response.status_code == 200, response.text


def test_existing_restricted_report_is_not_downloadable(client, headers, db):
    incident, _ = restricted_case(db)
    report = Report(
        title="Existing restricted report", kind="incident", requested_by=user_for(db, "analyst").id,
        options={"incident_id": incident.id}, storage_path="not-opened.pdf", status="completed",
    )
    db.add(report)
    db.commit()
    response = client.get(f"/api/v1/reports/{report.id}/download", headers=headers("analyst"))
    assert response.status_code == 403, response.text
    listing = client.get("/api/v1/reports", headers=headers("analyst"))
    assert listing.status_code == 200
    assert all(item["id"] != report.id for item in listing.json()["data"])


def test_analyst_cannot_link_restricted_indicator(client, headers, db):
    _, indicator = restricted_case(db)
    incident = Incident(title="Analyst owned case", owner_id=user_for(db, "analyst").id)
    db.add(incident)
    db.commit()
    response = client.post(
        f"/api/v1/incidents/{incident.id}/timeline", headers=headers("analyst"),
        json={"event_type": "note", "message": "Invalid link", "indicator_id": indicator.id},
    )
    assert response.status_code == 403, response.text


@pytest.mark.parametrize("role", ["analyst", "executive"])
def test_websocket_rejects_restricted_subscriptions(client, tokens, db, role):
    incident, _ = restricted_case(db)
    with client.websocket_connect(f"/api/v1/ws?token={tokens[role]}") as ws:
        assert ws.receive_json()["topic"] == "system.ready"
        ws.send_json({
            "action": "subscribe",
            "topics": [f"incidents.{incident.id}", "indicators.high_severity", "user.other"],
        })
        approved = ws.receive_json()["data"]["topics"]
        assert f"incidents.{incident.id}" not in approved
        assert "user.other" not in approved
        if role == "executive":
            assert "indicators.high_severity" not in approved
            assert "alerts.stream" not in approved


class Socket:
    def __init__(self):
        self.messages = []
        self.closed = False

    async def accept(self):
        pass

    async def close(self, **kwargs):
        self.closed = True

    async def send_json(self, message):
        self.messages.append(message)


def test_live_delivery_checks_clearance_and_sanitizes_payload(db):
    _, indicator = restricted_case(db)
    identities = {role: user_for(db, role).id for role in ("admin", "analyst", "executive")}

    async def exercise():
        manager = ConnectionManager()
        sockets = {}
        for role, user_id in identities.items():
            socket = Socket()
            sockets[role] = socket
            await manager.connect(socket, user_id, role, expires_at=time.time() + 60)
            manager.subscribe(socket, ["indicators.high_severity"])
        await manager._send("indicators.high_severity", {"id": indicator.id, "value": indicator.value, "tlp": "red"})
        assert not sockets["analyst"].messages
        assert not sockets["executive"].messages
        assert sockets["admin"].messages[0]["data"] == {"changed": True}

    asyncio.run(exercise())


def test_live_delivery_rechecks_current_role(db):
    analyst = user_for(db, "analyst")
    indicator = Indicator(type="domain", value=f"{uuid.uuid4().hex}.example", tlp="amber")
    db.add(indicator)
    db.commit()

    async def exercise():
        manager = ConnectionManager()
        socket = Socket()
        await manager.connect(socket, analyst.id, "analyst", expires_at=time.time() + 60)
        manager.subscribe(socket, ["indicators.high_severity"])
        analyst.role = "executive"
        db.commit()
        await manager._send("indicators.high_severity", {"id": indicator.id})
        assert not socket.messages

    try:
        asyncio.run(exercise())
    finally:
        analyst.role = "analyst"
        db.commit()


def test_expired_live_session_is_closed(db):
    admin = user_for(db, "admin")

    async def exercise():
        manager = ConnectionManager()
        socket = Socket()
        await manager.connect(socket, admin.id, "admin", expires_at=time.time() - 1)
        await manager._send("system.health", {"secret": "must not be sent"})
        assert socket.closed
        assert not socket.messages
        assert manager.count == 0

    asyncio.run(exercise())

import asyncio
import json
import os
import time
from uuid import uuid4

import pytest
import redis
from app import events, feeds
from app.correlation import _notify
from app.events import CHANNEL, ConnectionManager
from app.models import Alert, AlertRule, Feed, Incident, IncidentTimeline, Indicator, Notification, User
from sqlalchemy import select


def user_for(db, role):
    return db.scalar(select(User).where(User.role == role))


def case(db, tlp="red"):
    indicator = Indicator(value=f"{uuid4().hex}.example", type="domain", tlp=tlp)
    db.add(indicator)
    db.flush()
    alert = Alert(title="Restricted evidence", severity="high", tlp="amber", indicator_id=indicator.id)
    db.add(alert)
    db.commit()
    return indicator, alert


@pytest.mark.parametrize("role", ["admin", "analyst", "executive"])
def test_notification_creation_checks_clearance(db, role):
    indicator, alert = case(db)
    recipient = user_for(db, role)
    _notify(db, alert, indicator, [role])
    db.flush()
    result = db.scalar(select(Notification.id).where(
        Notification.user_id == recipient.id, Notification.link == f"/analyst?indicator={indicator.id}",
    ))
    assert (result is not None) == (role == "admin")


@pytest.mark.parametrize("target", ["indicator", "alert"])
def test_old_notifications_hide_after_reclassification(client, headers, db, target):
    analyst = user_for(db, "analyst")
    indicator, alert = case(db, "amber")
    target_id = indicator.id if target == "indicator" else alert.id
    notice = Notification(user_id=analyst.id, title="Evidence", body=indicator.value,
                          kind="alert", link=f"/analyst?{target}={target_id}")
    db.add(notice)
    db.commit()
    before = client.get("/api/v1/badges", headers=headers("analyst")).json()["data"]
    response = client.get("/api/v1/notifications", headers=headers("analyst"))
    assert notice.id in {row["id"] for row in response.json()["data"]}
    indicator.tlp = "red"
    db.commit()
    response = client.get("/api/v1/notifications", headers=headers("analyst"))
    assert notice.id not in {row["id"] for row in response.json()["data"]}
    assert indicator.value not in response.text
    after = client.get("/api/v1/badges", headers=headers("analyst")).json()["data"]
    assert after["unread_notifications"] == before["unread_notifications"] - 1
    assert after["new_alerts"] == before["new_alerts"] - 1


def test_notifications_recheck_changed_role(client, headers, db):
    analyst = user_for(db, "analyst")
    indicator, _ = case(db, "amber")
    notice = Notification(user_id=analyst.id, title="Previously visible", body=indicator.value,
                          link=f"/analyst?indicator={indicator.id}")
    db.add(notice)
    db.commit()
    try:
        analyst.role = "executive"
        db.commit()
        response = client.get("/api/v1/notifications", headers=headers("analyst"))
        assert response.status_code == 200
        assert response.json()["data"] == []
    finally:
        analyst.role = "analyst"
        db.commit()


def test_unresolvable_notification_links_are_hidden(client, headers, db):
    analyst = user_for(db, "analyst")
    notice = Notification(user_id=analyst.id, title="Legacy sensitive text", kind="alert", link=None)
    db.add(notice)
    db.commit()
    rows = client.get("/api/v1/notifications", headers=headers("analyst")).json()["data"]
    assert notice.id not in {row["id"] for row in rows}


def test_alert_list_and_mutations_check_linked_indicator(client, headers, db):
    _, alert = case(db)
    response = client.get("/api/v1/alerts", headers=headers("analyst"), params={"indicator_id": alert.indicator_id})
    assert response.json()["data"] == []
    assert response.json()["meta"]["total"] == 0
    response = client.patch(f"/api/v1/alerts/{alert.id}", headers=headers("analyst"), json={"status": "acknowledged"})
    assert response.status_code == 403
    response = client.get("/api/v1/alerts", headers=headers("admin"), params={"indicator_id": alert.indicator_id})
    assert alert.id in {row["id"] for row in response.json()["data"]}


def test_alert_and_assignment_notification_hide_restricted_incident(client, headers, db):
    red, _ = case(db)
    amber, alert = case(db, "amber")
    incident = Incident(title="Restricted incident title")
    db.add(incident)
    db.flush()
    db.add(IncidentTimeline(incident_id=incident.id, indicator_id=red.id, event_type="indicator", message="restricted"))
    alert.incident_id = incident.id
    notice = Notification(user_id=user_for(db, "analyst").id, title=incident.title,
                          kind="assignment", link=f"/analyst?alert={alert.id}")
    db.add(notice)
    db.commit()
    response = client.get("/api/v1/alerts", headers=headers("analyst"), params={"indicator_id": amber.id})
    assert response.json()["data"] == []
    assert incident.title not in response.text
    response = client.get("/api/v1/notifications", headers=headers("analyst"))
    assert notice.id not in {row["id"] for row in response.json()["data"]}


def test_assignment_rejects_insufficient_recipient_clearance(client, headers, db):
    _, alert = case(db)
    analyst = user_for(db, "analyst")
    response = client.patch(f"/api/v1/alerts/{alert.id}", headers=headers(), json={"assignee_id": analyst.id})
    assert response.status_code == 403
    db.refresh(alert)
    assert alert.assignee_id is None


def test_analyst_cannot_link_alert_to_restricted_incident(client, headers, db):
    red, _ = case(db)
    _, alert = case(db, "amber")
    incident = Incident(title="Hidden incident")
    db.add(incident)
    db.flush()
    db.add(IncidentTimeline(incident_id=incident.id, indicator_id=red.id, event_type="indicator", message="hidden"))
    db.commit()
    response = client.patch(f"/api/v1/alerts/{alert.id}", headers=headers("analyst"), json={"incident_id": incident.id})
    assert response.status_code == 403
    db.refresh(alert)
    assert alert.incident_id is None


def test_worker_without_event_loop_publishes_to_redis(monkeypatch):
    calls = []

    class Publisher:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def publish(self, channel, message):
            calls.append((channel, json.loads(message)))

    monkeypatch.setattr(events.settings, "redis_url", "redis://test.invalid/0")
    monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: Publisher())
    ConnectionManager().publish("alerts.stream", {"id": "saved-alert"})
    assert calls == [(CHANNEL, {"topic": "alerts.stream", "data": {"id": "saved-alert"}})]


def test_worker_publish_failure_is_logged_without_failing_saved_feed(monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise ConnectionError("Redis unavailable")

    monkeypatch.setattr(events.settings, "redis_url", "redis://test.invalid/0")
    monkeypatch.setattr(redis.Redis, "from_url", fail)
    ConnectionManager().publish("system.health", {"status": "success"})
    assert "Worker could not publish" in caplog.text


def test_feed_publishes_all_alerts_and_high_severity_indicators(db, monkeypatch):
    name = "test-feed-" + uuid4().hex
    feed = Feed(name=name, kind="test-delivery")
    rule = AlertRule(name=name, min_score=40, sources=[name], tlp_max="red", route_roles=["admin"])
    db.add_all([feed, rule])
    db.commit()
    records = [{"value": f"{index}-{uuid4().hex}.example", "type": "domain", "confidence": 100,
                "reliability": 1, "malicious_ratio": 1, "kev": True} for index in range(25)]
    monkeypatch.setitem(feeds.FETCHERS, "test-delivery", lambda _feed: records)
    delivered = []
    monkeypatch.setattr(feeds.manager, "publish", lambda topic, payload: delivered.append((topic, payload)))
    monkeypatch.setattr(feeds, "send_outbound_alert", lambda _alert: None)
    result = feeds.run_feed(feed.id)
    assert result["ok"], result
    assert result["processed"] == 25
    assert result["alerts"] >= 25
    assert len([data for topic, data in delivered if topic == "alerts.stream"]) == result["alerts"]
    indicator_ids = set(db.scalars(select(Indicator.id).where(Indicator.value.in_([row["value"] for row in records]))))
    assert {data["id"] for topic, data in delivered if topic == "indicators.high_severity"} == indicator_ids


if os.getenv("THREATLENS_TEST_REDIS_URL"):
    def test_real_redis_worker_message_reaches_authorized_socket(db, monkeypatch):
        url = os.environ["THREATLENS_TEST_REDIS_URL"]
        monkeypatch.setattr(events.settings, "redis_url", url)
        admin_id = user_for(db, "admin").id

        async def exercise():
            delivered = asyncio.Event()
            messages = []

            class Socket:
                async def accept(self):
                    pass

                async def send_json(self, message):
                    messages.append(message)
                    delivered.set()

            manager = ConnectionManager()
            manager.bind_loop(asyncio.get_running_loop())
            await manager.connect(Socket(), admin_id, "admin", expires_at=time.time() + 30)
            try:
                assert await manager.start_redis()
                async def subscribed():
                    while not (await manager._redis.pubsub_numsub(CHANNEL))[0][1]:
                        await asyncio.sleep(0.02)

                await asyncio.wait_for(subscribed(), timeout=3)
                await asyncio.to_thread(ConnectionManager().publish, "system.health", {"sensitive": "redacted"})
                await asyncio.wait_for(delivered.wait(), timeout=3)
                assert messages == [{"topic": "system.health", "ts": messages[0]["ts"], "data": {"changed": True}}]
            finally:
                await manager.stop_redis()

        asyncio.run(exercise())

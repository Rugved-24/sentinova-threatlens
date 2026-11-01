from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app import enrichment
from app.correlation import _notify, _rule_matches
from app.db import engine
from app.feeds import parse_csv_records
from app.models import Alert, AlertRule, AuditLog, Indicator, IndicatorSource, Notification, User
from sqlalchemy import inspect, select


def test_csv_parser_normalizes_common_headers():
    content = (
        "ioc,indicator_type,source,confidence,reliability,tlp,tags,attack_ids,first_seen\n"
        "Example.COM.,domain,Partner CSV,88,0.9,green,phishing;campaign,T1566,2026-10-01T10:00:00Z\n"
    )
    records = parse_csv_records(content)
    assert records == [
        {
            "value": "Example.COM.",
            "type": "domain",
            "source": "Partner CSV",
            "confidence": 88,
            "reliability": 0.9,
            "tags": ["phishing", "campaign"],
            "attack_ids": ["T1566"],
            "notes": "",
            "tlp": "green",
            "first_seen": datetime(2026, 10, 1, 10, 0),
            "kev": False,
            "malicious_ratio": 0.7,
            "raw_ref": "",
        } | {"last_seen": records[0]["last_seen"]}
    ]


def test_csv_import_endpoint_ingests_and_audits(client, headers, db):
    suffix = uuid4().hex
    csv_data = f"value,type,confidence,tlp,tags\n{suffix}.example,domain,91,amber,imported\n"
    response = client.post(
        "/api/v1/feeds/import/csv",
        headers=headers("admin"),
        data={"source": "Acceptance CSV", "tlp": "amber"},
        files={"file": ("iocs.csv", csv_data, "text/csv")},
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["created"] == 1
    indicator = db.scalar(select(Indicator).where(Indicator.value == f"{suffix}.example"))
    assert indicator
    provenance = db.scalar(
        select(IndicatorSource).where(
            IndicatorSource.indicator_id == indicator.id,
            IndicatorSource.source_name == "Acceptance CSV",
        )
    )
    assert provenance and provenance.source_confidence == 91
    assert db.scalar(select(AuditLog).where(AuditLog.action == "feed.csv_import"))


def test_csv_import_rejects_missing_indicator_column(client, headers):
    response = client.post(
        "/api/v1/feeds/import/csv",
        headers=headers("admin"),
        data={"source": "Bad CSV", "tlp": "amber"},
        files={"file": ("bad.csv", "name,score\nexample,50\n", "text/csv")},
    )
    assert response.status_code == 422
    assert response.json()["error_code"] == "invalid_csv"


def test_verdict_aggregation_preserves_independent_evidence():
    result = enrichment._aggregate_verdicts(
        [
            {"provider": "AbuseIPDB", "malicious_ratio": 0.8, "verdict": "malicious"},
            {"provider": "VirusTotal", "malicious_ratio": 0.4, "verdict": "unknown"},
        ]
    )
    assert result and result["provider_count"] == 2
    assert result["malicious_ratio"] == 0.6
    assert result["verdict"] == "malicious"


def test_domain_age_evidence_is_aggregated():
    result = enrichment._aggregate_verdicts(
        [
            {
                "provider": "VirusTotal",
                "malicious_ratio": 0.2,
                "verdict": "unknown",
                "domain_age_days": 4,
                "newly_registered": True,
            }
        ]
    )
    assert result and result["domain_age_days"] == 4
    assert result["newly_registered"] is True


def test_rule_category_and_individual_user_routing(db):
    target = db.scalar(select(User).where(User.role == "analyst", User.is_active.is_(True)))
    other = db.scalar(select(User).where(User.role == "hunter", User.is_active.is_(True)))
    indicator = Indicator(
        value=f"{uuid4().hex}.example",
        type="domain",
        tlp="amber",
        severity_score=90,
        first_seen=datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1),
    )
    alert = Alert(title="Targeted", severity="critical", score=90, tlp="amber")
    rule = AlertRule(name=uuid4().hex, categories=["critical-risk"], min_score=80)
    db.add_all([indicator, alert, rule])
    db.flush()
    assert _rule_matches(rule, indicator, set(), {"critical-risk"})
    assert not _rule_matches(rule, indicator, set(), {"network"})
    _notify(db, alert, indicator, [], [target.id])
    db.flush()
    assert db.scalar(
        select(Notification).where(
            Notification.user_id == target.id,
            Notification.title == "Critical alert: domain indicator",
        )
    )
    assert not db.scalar(
        select(Notification).where(
            Notification.user_id == other.id,
            Notification.title == "Critical alert: domain indicator",
        )
    )


def test_alert_rule_migration_columns_exist():
    columns = {column["name"] for column in inspect(engine).get_columns("alert_rules")}
    assert {"categories", "route_user_ids"}.issubset(columns)


def test_readiness_and_notification_mutation_audit(client, headers, db):
    assert client.get("/api/v1/ready").json()["status"] == "ready"
    user = db.scalar(select(User).where(User.role == "analyst", User.is_active.is_(True)))
    note = Notification(user_id=user.id, title=f"Audit {uuid4().hex}")
    db.add(note)
    db.commit()
    response = client.patch(
        "/api/v1/notifications/read",
        headers=headers("analyst"),
        json={"ids": [note.id]},
    )
    assert response.status_code == 200
    assert response.json()["data"]["updated"] == 1
    assert db.scalar(
        select(AuditLog).where(
            AuditLog.action == "notification.read",
            AuditLog.actor_id == user.id,
        )
    )

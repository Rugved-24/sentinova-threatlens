from __future__ import annotations

import json
import logging
import os

from sqlalchemy import func, select

from .audit import record_audit
from .config import ROOT, get_settings
from .correlation import append_timeline, correlate_indicator, create_alerts_for_indicator
from .db import SessionLocal, init_db
from .demo import generate_demo_records, generate_relationships, generate_security_events
from .ingest import add_relationship, upsert_indicator
from .models import (
    Alert,
    AlertRule,
    AttackTechnique,
    Feed,
    Incident,
    Indicator,
    SavedHunt,
    SecurityEvent,
    User,
)
from .reporting import generate_report
from .security import encrypt_json, hash_password

logger = logging.getLogger("threatlens.seed")
settings = get_settings()

DEMO_PASSWORD = os.getenv("THREATLENS_DEMO_PASSWORD", "ThreatLens#2026!")
DEMO_USERS = [
    ("admin@threatlens.io", "Aarav Mehta", "admin"),
    ("engineer@threatlens.io", "Elena Fischer", "engineer"),
    ("responder@threatlens.io", "Daniel Okafor", "responder"),
    ("hunter@threatlens.io", "Mei Lin Tan", "hunter"),
    ("analyst@threatlens.io", "Priya Nair", "analyst"),
    ("exec@threatlens.io", "Rachel Adeyemi", "executive"),
]

DEFAULT_WIDGETS = ["posture", "kpis", "risk", "mix", "heatmap", "indicators"]


def current_password() -> str:
    return os.getenv("THREATLENS_DEMO_PASSWORD", DEMO_PASSWORD)


def _techniques(db) -> int:
    path = ROOT / "data" / "attack_techniques.json"
    if not path.exists():
        logger.warning("ATT&CK dataset not found at %s", path)
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    inserted = 0
    for item in payload.get("techniques", []):
        technique_id = str(item.get("id", ""))[:16]
        if not technique_id or db.get(AttackTechnique, technique_id):
            continue
        db.add(
            AttackTechnique(
                id=technique_id,
                name=str(item.get("name", ""))[:160],
                tactic=str(item.get("tactic", "uncategorized"))[:64],
                description=str(item.get("description", ""))[:1000],
                url=str(item.get("url", ""))[:500],
                platforms=[str(value)[:32] for value in (item.get("platforms") or [])[:10]],
            )
        )
        inserted += 1
    return inserted


def _feeds(db) -> int:
    definitions = [
        ("ThreatLens Demo Feed", "demo", None, True, 30),
        (
            "CISA KEV",
            "kev",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            True,
            720,
        ),
        ("OpenPhish", "openphish", "https://openphish.com/feed.txt", True, 60),
        (
            "Feodo Tracker",
            "feodo",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            True,
            60,
        ),
        ("Blocklist.de", "blocklistde", "https://lists.blocklist.de/lists/all.txt", True, 120),
        (
            "ET Compromised",
            "et_compromised",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            True,
            120,
        ),
        ("CINS Bad Guys", "cins", "https://cinsscore.com/list/ci-badguys.txt", True, 120),
        (
            "Phishing Army",
            "phishing_army",
            "https://phishing.army/download/phishing_army_blocklist_extended.txt",
            True,
            180,
        ),
        ("URLhaus", "urlhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/", False, 120),
        (
            "AlienVault OTX",
            "otx",
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
            bool(settings.otx_api_key),
            120,
        ),
        (
            "AbuseIPDB Blacklist",
            "abuseipdb",
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100",
            bool(settings.abuseipdb_api_key),
            120,
        ),
        (
            "ThreatFox",
            "threatfox",
            "https://threatfox-api.abuse.ch/api/v1/",
            bool(settings.threatfox_api_key),
            120,
        ),
        ("TAXII Collection", "taxii", None, False, 180),
    ]
    inserted = 0
    for name, kind, url, enabled, schedule in definitions:
        if db.execute(select(Feed).where(Feed.name == name)).scalar_one_or_none():
            continue
        auth = None
        if kind == "otx" and settings.otx_api_key:
            auth = encrypt_json({"X-OTX-API-KEY": settings.otx_api_key})
        elif kind == "abuseipdb" and settings.abuseipdb_api_key:
            auth = encrypt_json({"Key": settings.abuseipdb_api_key})
        elif kind == "threatfox" and settings.threatfox_api_key:
            auth = encrypt_json({"Auth-Key": settings.threatfox_api_key})
        db.add(
            Feed(
                name=name,
                kind=kind,
                url=url,
                auth_header_enc=auth,
                enabled=enabled,
                schedule_minutes=schedule,
                config={"note": "Configure an API key to enable this feed."}
                if kind in {"otx", "abuseipdb", "threatfox"} and not enabled
                else {},
            )
        )
        inserted += 1
    return inserted


def _alert_rules(db) -> int:
    rules = [
        ("Critical Indicators", 80, [], ["admin", "responder"], "red"),
        ("High-Risk IP Infrastructure", 70, ["ip"], ["analyst", "responder"], "red"),
        ("Malware Hash Detection", 72, ["hash_md5", "hash_sha1", "hash_sha256"], ["analyst", "responder"], "red"),
        ("Known Exploited Vulnerabilities", 55, ["cve"], ["admin", "analyst"], "red"),
    ]
    inserted = 0
    for name, score, types, roles, tlp_max in rules:
        if db.execute(select(AlertRule).where(AlertRule.name == name)).scalar_one_or_none():
            continue
        db.add(
            AlertRule(
                name=name,
                enabled=True,
                min_score=score,
                types=types,
                sources=[],
                tlp_max=tlp_max,
                route_roles=roles,
            )
        )
        inserted += 1
    return inserted


def _users(db) -> int:
    if db.execute(select(func.count()).select_from(User)).scalar_one() > 0:
        return 0
    inserted = 0
    if settings.demo_mode:
        for email, name, role in DEMO_USERS:
            db.add(
                User(
                    email=email,
                    name=name,
                    role=role,
                    password_hash=hash_password(current_password()),
                    preferences={"widgets": DEFAULT_WIDGETS},
                )
            )
            inserted += 1
    elif settings.admin_email and settings.admin_password:
        db.add(
            User(
                email=settings.admin_email.lower(),
                name="ThreatLens Administrator",
                role="admin",
                password_hash=hash_password(settings.admin_password),
                preferences={"widgets": DEFAULT_WIDGETS},
            )
        )
        inserted += 1
    return inserted


def _demo_data(db, admin: User) -> dict:
    records = generate_demo_records(count=64)
    indicators = []
    for record in records:
        indicator, _ = upsert_indicator(
            db,
            value=record["value"],
            kind=record.get("type"),
            source=record["source"],
            confidence=int(record["confidence"]),
            reliability=float(record["reliability"]),
            tlp=record["tlp"],
            tags=record["tags"],
            attack_ids=record["attack_ids"],
            notes=record["notes"],
            first_seen=record["first_seen"],
            last_seen=record["last_seen"],
            kev=record["kev"],
            malicious_ratio=record["malicious_ratio"],
            geo=record["geo"],
            country=record["geo"].get("country_code"),
            asn=record["geo"].get("asn"),
        )
        if indicator:
            indicators.append(indicator)
    db.flush()

    for edge in generate_relationships(records):
        source_value, target_value, target_kind, relation = edge
        source = db.execute(
            select(Indicator).where(Indicator.value == source_value)
        ).scalars().first()
        if source is None:
            continue
        add_relationship(
            db,
            source,
            target_value,
            target_kind,
            relation,
            source_name="ThreatLens Demo Feed",
            confidence=70,
            reliability=0.6,
            tlp=source.tlp,
        )

    for event in generate_security_events(records):
        db.add(SecurityEvent(**event))
    db.flush()

    for indicator in indicators:
        correlate_indicator(db, indicator)
    db.flush()

    top = db.execute(
        select(Indicator)
        .where(Indicator.status == "active")
        .order_by(Indicator.severity_score.desc(), Indicator.internal_sightings.desc())
        .limit(12)
    ).scalars().all()
    alert_count = 0
    for indicator in top:
        events = correlate_indicator(db, indicator)
        alert_count += len(create_alerts_for_indicator(db, indicator, events))
    db.flush()
    return {
        "indicators": len(indicators),
        "events": 22,
        "alerts": alert_count,
    }


def _incidents(db, responder: User) -> int:
    existing = db.execute(
        select(func.count())
        .select_from(Incident)
        .where(
            Incident.title.in_(
                [
                    "Credential phishing wave targeting finance",
                    "Suspected C2 beaconing from EDGE-447",
                ]
            )
        )
    ).scalar_one()
    if existing:
        return 0
    alerts = db.execute(select(Alert).order_by(Alert.score.desc()).limit(20)).scalars().all()
    available = [alert for alert in alerts if alert.incident_id is None]
    phishing = available[:3]
    c2 = available[3:6]
    created = 0
    incident_specs = [
        (
            "Credential phishing wave targeting finance",
            "Multiple phishing URLs and newly observed domains correlate with credential "
            "harvesting attempts against finance staff. Messages were reported by internal "
            "mail gateway telemetry and matched active feed intelligence.",
            "high",
            phishing,
            ["triage", "scope"],
        ),
        (
            "Suspected C2 beaconing from EDGE-447",
            "Periodic outbound connections from a workstation match active botnet C2 "
            "infrastructure. The endpoint remains quarantined pending forensic review.",
            "critical",
            c2,
            ["triage", "scope", "contain"],
        ),
    ]
    for title, summary, severity, linked, done_ids in incident_specs:
        if not linked:
            continue
        incident = Incident(
            title=title,
            summary=summary,
            severity=severity,
            status="investigating",
            owner_id=responder.id,
            checklist=[
                {"id": "triage", "label": "Validate alerts and indicators", "done": "triage" in done_ids},
                {"id": "scope", "label": "Scope affected assets and identities", "done": "scope" in done_ids},
                {"id": "contain", "label": "Contain affected assets", "done": "contain" in done_ids},
                {"id": "eradicate", "label": "Eradicate threat and recover", "done": False},
                {"id": "report", "label": "Generate final incident report", "done": False},
            ],
        )
        db.add(incident)
        db.flush()
        append_timeline(
            db,
            incident.id,
            "created",
            f"Incident opened by {responder.name} during demo initialization.",
            actor_id=responder.id,
        )
        for alert in linked:
            alert.incident_id = incident.id
            append_timeline(
                db,
                incident.id,
                "alert",
                f"Linked alert: {alert.title} ({alert.score}/100).",
                actor_id=responder.id,
                indicator_id=alert.indicator_id,
                meta={"alert_id": alert.id},
            )
        append_timeline(
            db,
            incident.id,
            "observation",
            "Internal telemetry correlation established; containment checklist updated.",
            actor_id=responder.id,
        )
        created += 1
    return created


def _hunts(db, hunter: User | None) -> int:
    if hunter is None:
        return 0
    existing = db.execute(
        select(func.count()).select_from(SavedHunt).where(SavedHunt.created_by == hunter.id)
    ).scalar_one()
    if existing:
        return 0
    db.add(
        SavedHunt(
            name="High-severity C2 infrastructure",
            query={"q": "", "type": ["ip"], "severity_min": 70, "search": {"tag": "c2"}},
            created_by=hunter.id,
        )
    )
    db.add(
        SavedHunt(
            name="Known exploited vulnerabilities",
            query={"q": "", "type": ["cve"], "search": {"kev": True}},
            created_by=hunter.id,
        )
    )
    return 2


def seed_database() -> dict:
    init_db()
    with SessionLocal() as db:
        if db.execute(select(func.count()).select_from(User)).scalar_one() > 0:
            return {"seeded": False, "reason": "database already initialized"}
        techniques = _techniques(db)
        users = _users(db)
        feeds = _feeds(db)
        rules = _alert_rules(db)
        db.flush()
        admin = db.execute(select(User).where(User.role == "admin")).scalars().first()
        responder = db.execute(select(User).where(User.role == "responder")).scalars().first()
        hunter = db.execute(select(User).where(User.role == "hunter")).scalars().first()
        demo = _demo_data(db, admin) if settings.demo_mode and admin else {"indicators": 0}
        incidents = _incidents(db, responder) if settings.demo_mode and responder else 0
        hunts = _hunts(db, hunter)
        record_audit(
            db,
            "system.seed",
            actor=admin,
            object_type="system",
            detail={
                "techniques": techniques,
                "users": users,
                "feeds": feeds,
                "rules": rules,
                "demo": demo,
                "incidents": incidents,
            },
        )
        db.commit()
        summary = {
            "seeded": True,
            "techniques": techniques,
            "users": users,
            "feeds": feeds,
            "rules": rules,
            "demo": demo,
            "incidents": incidents,
            "hunts": hunts,
        }
    if settings.demo_mode and admin:
        try:
            with SessionLocal() as db:
                admin = db.get(User, admin.id)
                report = generate_report(
                    db,
                    user=admin,
                    title="Baseline Threat Intelligence Brief",
                    kind="executive",
                )
                record_audit(
                    db,
                    "report.seed",
                    actor=admin,
                    object_type="report",
                    object_id=report.id,
                    detail={"title": report.title},
                )
                db.commit()
                summary["report"] = report.id
        except Exception:
            logger.exception("Unable to generate the seed report")
    if settings.search_backend == "elasticsearch":
        try:
            from .indexing import rebuild_all

            with SessionLocal() as db:
                summary["indexed_documents"] = rebuild_all(db)
        except Exception:
            logger.exception("Unable to project the seed into Elasticsearch")
    return summary


def ensure_seed() -> None:
    try:
        summary = seed_database()
        if summary.get("seeded"):
            logger.info("ThreatLens seed complete: %s", summary)
    except Exception:
        logger.exception("Seed failed")
        raise

from __future__ import annotations

import contextlib
import csv
import hashlib
import hmac
import io
import json
import time
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select

from .audit import record_audit
from .config import get_settings
from .correlation import correlate_indicator, create_alerts_for_indicator
from .db import session_scope
from .demo import generate_demo_records
from .events import manager
from .ingest import upsert_indicator
from .models import Feed, Indicator
from .normalize import parse_stix_pattern
from .security import decrypt_json, validate_outbound_url
from .utils import iso, utcnow

settings = get_settings()
UA = {"User-Agent": "ThreatLens/1.0 (SOC threat intelligence ingestion)"}

RELIABILITY = {
    "demo": 0.55,
    "kev": 1.0,
    "urlhaus": 0.9,
    "openphish": 0.8,
    "feodo": 0.92,
    "blocklistde": 0.7,
    "et_compromised": 0.78,
    "cins": 0.75,
    "phishing_army": 0.72,
    "otx": 0.65,
    "abuseipdb": 0.85,
    "threatfox": 0.88,
    "taxii": 0.8,
}

FEED_DEFAULTS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "openphish": "https://openphish.com/feed.txt",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "blocklistde": "https://lists.blocklist.de/lists/all.txt",
    "et_compromised": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "cins": "https://cinsscore.com/list/ci-badguys.txt",
    "phishing_army": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "otx": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
    "abuseipdb": "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100",
    "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
}


class SystemActor:
    id = None
    email = "system@threatlens.local"


def _headers(feed: Feed) -> dict[str, str]:
    headers = dict(UA)
    if feed.auth_header_enc:
        with contextlib.suppress(ValueError):
            headers.update(decrypt_json(feed.auth_header_enc))
    return headers


def _get(
    url: str,
    feed: Feed,
    *,
    method: str = "GET",
    payload: dict | None = None,
    accept: str = "application/json",
) -> httpx.Response:
    validate_outbound_url(url)
    headers = _headers(feed)
    headers["Accept"] = accept
    with httpx.Client(timeout=settings.feed_timeout_seconds, follow_redirects=False) as client:
        response = client.request(method, url, headers=headers, json=payload)
        if 300 <= response.status_code < 400:
            raise ValueError("Feed redirected; redirects are refused for SSRF safety")
        response.raise_for_status()
        return response


def _json(url: str, feed: Feed, **kwargs) -> Any:
    return _get(url, feed, **kwargs).json()


def _text(url: str, feed: Feed) -> str:
    return _get(url, feed, accept="text/plain").text


def _record(
    value: str,
    kind: str | None,
    *,
    source: str,
    confidence: int,
    reliability: float,
    tags: list[str] | None = None,
    attack_ids: list[str] | None = None,
    notes: str = "",
    tlp: str = "amber",
    first_seen=None,
    last_seen=None,
    kev: bool = False,
    malicious_ratio: float = 0.7,
    raw_ref: str = "",
) -> dict:
    return {
        "value": value,
        "type": kind,
        "source": source,
        "confidence": confidence,
        "reliability": reliability,
        "tags": tags or [],
        "attack_ids": attack_ids or [],
        "notes": notes,
        "tlp": tlp,
        "first_seen": first_seen,
        "last_seen": last_seen or utcnow(),
        "kev": kev,
        "malicious_ratio": malicious_ratio,
        "raw_ref": raw_ref,
    }


def parse_csv_records(
    content: str,
    *,
    source: str = "CSV Import",
    default_tlp: str = "amber",
    limit: int = 2000,
) -> list[dict]:
    """Convert a header-based IOC CSV into normalised feed records."""
    reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
    fields = {str(name).strip().lower() for name in (reader.fieldnames or []) if name}
    if not fields.intersection({"value", "indicator", "ioc"}):
        raise ValueError("CSV requires a value, indicator, or ioc column")

    def pick(row: dict, *names: str) -> str:
        lowered = {str(key).strip().lower(): value for key, value in row.items() if key}
        return str(next((lowered[name] for name in names if lowered.get(name)), "")).strip()

    def split_values(value: str) -> list[str]:
        return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]

    def timestamp(value: str):
        if not value:
            return None
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        return None

    records = []
    for row in reader:
        if len(records) >= limit:
            break
        value = pick(row, "value", "indicator", "ioc")
        if not value:
            continue
        try:
            confidence = max(0, min(100, int(pick(row, "confidence") or 60)))
        except ValueError:
            confidence = 60
        try:
            reliability = max(0.05, min(1.0, float(pick(row, "reliability") or 0.7)))
        except ValueError:
            reliability = 0.7
        records.append(
            _record(
                value,
                pick(row, "type", "indicator_type", "kind") or None,
                source=pick(row, "source", "source_name") or source,
                confidence=confidence,
                reliability=reliability,
                tags=split_values(pick(row, "tags", "tag")),
                attack_ids=split_values(pick(row, "attack_ids", "attack", "mitre_attack")),
                notes=pick(row, "notes", "description")[:1200],
                tlp=pick(row, "tlp", "tlp_marking") or default_tlp,
                first_seen=timestamp(pick(row, "first_seen")),
                last_seen=timestamp(pick(row, "last_seen")),
                raw_ref=pick(row, "raw_ref", "reference", "id")[:500],
            )
        )
    return records


def fetch_kev(feed: Feed) -> list[dict]:
    payload = _json(feed.url or FEED_DEFAULTS["kev"], feed)
    records = []
    for item in payload.get("vulnerabilities", [])[:100]:
        cve = item.get("cveID", "")
        records.append(
            _record(
                cve,
                "cve",
                source="CISA KEV",
                confidence=98,
                reliability=RELIABILITY["kev"],
                tags=["cisa-kev", "known-exploited", "vulnerability"],
                attack_ids=["T1190"],
                notes=(
                    f"{item.get('vendorProject', '')} {item.get('product', '')}: "
                    f"{item.get('shortDescription', '')} Required action: "
                    f"{item.get('requiredAction', '')}"
                )[:1200],
                tlp="clear",
                first_seen=utcnow(),
                last_seen=utcnow(),
                kev=True,
                malicious_ratio=0.95,
                raw_ref=item.get("cveID", ""),
            )
        )
    return records


def fetch_urlhaus(feed: Feed) -> list[dict]:
    payload = _json(feed.url or FEED_DEFAULTS["urlhaus"], feed)
    items = payload if isinstance(payload, list) else payload.get("urls", [])
    records = []
    for item in items[:150]:
        url = item.get("url") or item.get("urlhaus_link")
        if not url:
            continue
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        records.append(
            _record(
                url,
                "url",
                source="URLhaus",
                confidence=85,
                reliability=RELIABILITY["urlhaus"],
                tags=["urlhaus", *tags[:5]],
                attack_ids=["T1105"],
                notes=f"URLhaus status: {item.get('url_status', 'unknown')}; threat: {item.get('threat', 'unknown')}",
                tlp="amber",
                malicious_ratio=0.85,
                raw_ref=item.get("id") if item.get("id") else None,
            )
        )
    return records


def fetch_openphish(feed: Feed) -> list[dict]:
    text = _text(feed.url or FEED_DEFAULTS["openphish"], feed)
    records = []
    for line in text.splitlines()[:200]:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        records.append(
            _record(
                value,
                "url",
                source="OpenPhish",
                confidence=75,
                reliability=RELIABILITY["openphish"],
                tags=["openphish", "phishing"],
                attack_ids=["T1566"],
                notes="Active phishing URL reported by OpenPhish.",
                malicious_ratio=0.75,
            )
        )
    return records


def fetch_feodo(feed: Feed) -> list[dict]:
    payload = _json(feed.url or FEED_DEFAULTS["feodo"], feed)
    items = payload if isinstance(payload, list) else payload.get("data", [])
    records = []
    for item in items[:200]:
        ip = item.get("ip_address") or item.get("ip")
        if not ip:
            continue
        records.append(
            _record(
                ip,
                "ip",
                source="Feodo Tracker",
                confidence=88,
                reliability=RELIABILITY["feodo"],
                tags=["feodo", "botnet", "c2"],
                attack_ids=["T1071", "T1095"],
                notes=(
                    f"Feodo botnet C2. Malware family: {item.get('malware', 'unknown')}; "
                    f"port {item.get('port', '?')}"
                ),
                malicious_ratio=0.9,
                raw_ref=item.get("first_seen"),
            )
        )
    return records


def _ip_blocklist(feed: Feed, source: str, tags: list[str], confidence: int) -> list[dict]:
    text = _text(feed.url, feed)
    records = []
    for line in text.splitlines()[:400]:
        value = line.strip()
        if not value or value.startswith("#") or value.startswith(";"):
            continue
        value = value.split()[0]
        if "/" in value or value.replace(".", "").isdigit() is False:
            continue
        records.append(
            _record(
                value,
                "ip",
                source=source,
                confidence=confidence,
                reliability=RELIABILITY.get(feed.kind, 0.7),
                tags=tags,
                attack_ids=["T1595"],
                notes=f"{source} blocklist entry. Reputation-only signal; validate before action.",
                malicious_ratio=0.6,
            )
        )
    return records


def fetch_blocklistde(feed: Feed) -> list[dict]:
    return _ip_blocklist(feed, "Blocklist.de", ["blocklist", "abuse"], 65)


def fetch_et_compromised(feed: Feed) -> list[dict]:
    return _ip_blocklist(feed, "ET Compromised", ["blocklist", "compromised"], 72)


def fetch_cins(feed: Feed) -> list[dict]:
    return _ip_blocklist(feed, "CINS Bad Guys", ["blocklist", "scanner"], 68)


def fetch_phishing_army(feed: Feed) -> list[dict]:
    text = _text(feed.url, feed)
    records = []
    for line in text.splitlines()[:300]:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        value = value.split()[0]
        if value.startswith("0.0.0.0 "):
            value = value.split(" ", 1)[1]
        records.append(
            _record(
                value,
                None,
                source="Phishing Army",
                confidence=70,
                reliability=RELIABILITY["phishing_army"],
                tags=["phishing", "blocklist"],
                attack_ids=["T1566"],
                notes="Domain appears in the Phishing Army community blocklist.",
                malicious_ratio=0.65,
            )
        )
    return records


def fetch_otx(feed: Feed) -> list[dict]:
    payload = _json(feed.url or FEED_DEFAULTS["otx"], feed)
    type_map = {
        "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
        "URL": "url", "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256", "email": "email", "CVE": "cve",
    }
    tlp_map = {"TLP:WHITE": "clear", "TLP:GREEN": "green", "TLP:AMBER": "amber", "TLP:RED": "red"}
    records = []
    for pulse in payload.get("results", [])[:20]:
        pulse_tags = [str(tag)[:32] for tag in pulse.get("tags", [])[:5]]
        tlp = tlp_map.get(str(pulse.get("tlp", "TLP:AMBER")).upper(), "amber")
        for indicator in pulse.get("indicators", [])[:25]:
            kind = type_map.get(indicator.get("type"))
            if not kind:
                continue
            records.append(
                _record(
                    indicator.get("indicator", ""),
                    kind,
                    source="AlienVault OTX",
                    confidence=65,
                    reliability=RELIABILITY["otx"],
                    tags=["otx", *pulse_tags],
                    attack_ids=["T1071"],
                    notes=f"OTX pulse: {pulse.get('name', '')[:180]}",
                    tlp=tlp,
                    malicious_ratio=0.7,
                    raw_ref=pulse.get("id"),
                )
            )
    return records


def fetch_abuseipdb(feed: Feed) -> list[dict]:
    payload = _json(feed.url or FEED_DEFAULTS["abuseipdb"], feed)
    records = []
    for item in payload.get("data", [])[:200]:
        score = int(item.get("abuseConfidenceScore", 0))
        records.append(
            _record(
                item.get("ipAddress", ""),
                "ip",
                source="AbuseIPDB Blacklist",
                confidence=max(60, score),
                reliability=RELIABILITY["abuseipdb"],
                tags=["abuseipdb", "reputation"],
                attack_ids=["T1595"],
                notes=(
                    f"AbuseIPDB confidence {score}; reports {item.get('totalReports', 0)}; "
                    f"country {item.get('countryCode', '?')}"
                ),
                malicious_ratio=min(1.0, score / 100),
                raw_ref=item.get("lastReportedAt"),
            )
        )
    return records


def fetch_threatfox(feed: Feed) -> list[dict]:
    payload = _json(
        feed.url or FEED_DEFAULTS["threatfox"],
        feed,
        method="POST",
        payload={"query": "get_iocs", "days": 2},
    )
    items = payload.get("data", []) if isinstance(payload.get("data"), list) else []
    records = []
    for item in items[:200]:
        value = str(item.get("ioc", ""))
        ioc_type = str(item.get("ioc_type", ""))
        if ioc_type.startswith("ip"):
            value = value.split(":")[0]
            kind = "ip"
        elif ioc_type in {"domain", "hostname"}:
            kind = "domain"
        elif ioc_type == "url":
            kind = "url"
        elif ioc_type == "md5_hash":
            kind = "hash_md5"
        elif ioc_type == "sha256_hash":
            kind = "hash_sha256"
        else:
            continue
        confidence_map = {"100": 90, "75": 75, "50": 55, "25": 40}
        confidence = confidence_map.get(str(item.get("confidence_level", "50")), 55)
        records.append(
            _record(
                value,
                kind,
                source="ThreatFox",
                confidence=confidence,
                reliability=RELIABILITY["threatfox"],
                tags=["threatfox", *[str(tag)[:24] for tag in (item.get("tags") or [])[:5]]],
                attack_ids=["T1071"],
                notes=f"ThreatFox malware family: {item.get('malware_printable') or item.get('malware', 'unknown')}",
                malicious_ratio=min(0.95, confidence / 100 + 0.1),
                raw_ref=str(item.get("id", "")),
            )
        )
    return records


def fetch_taxii(feed: Feed) -> list[dict]:
    config = feed.config or {}
    discovery_url = config.get("discovery_url") or feed.url
    if not discovery_url:
        raise ValueError("TAXII discovery URL is not configured")
    discovery = _json(discovery_url, feed)
    api_root = ""
    roots = discovery.get("api_roots") or []
    if roots:
        api_root = roots[0]
    elif discovery.get("default"):
        api_root = discovery["default"]
    if not api_root:
        raise ValueError("TAXII discovery did not return an API root")
    collections_url = api_root.rstrip("/") + "/collections/"
    collections = _json(
        collections_url, feed, accept="application/taxii+json;version=2.1"
    ).get("collections", [])
    collection_id = config.get("collection_id")
    if not collection_id:
        readable = [item for item in collections if item.get("can_read", True)]
        if not readable:
            raise ValueError("No readable TAXII collections")
        collection_id = readable[0]["id"]
    objects_url = f"{collections_url}{collection_id}/objects/?limit=200"
    payload = _json(objects_url, feed, accept="application/taxii+json;version=2.1")
    records = []
    for obj in payload.get("objects", [])[:300]:
        if obj.get("type") != "indicator" or not obj.get("pattern"):
            continue
        for value, kind in parse_stix_pattern(obj["pattern"]):
            records.append(
                _record(
                    value,
                    kind,
                    source="TAXII Collection",
                    confidence=72,
                    reliability=RELIABILITY["taxii"],
                    tags=["taxii", *[str(label)[:24] for label in obj.get("labels", [])[:5]]],
                    attack_ids=["T1071"],
                    notes=f"TAXII indicator: {obj.get('name', '')[:180]}",
                    tlp="amber",
                    malicious_ratio=0.75,
                    raw_ref=obj.get("id"),
                )
            )
    return records


def fetch_demo(feed: Feed) -> list[dict]:
    seed = int(time.time() // 1800)
    return generate_demo_records(count=24, days=8, seed=seed)


FETCHERS = {
    "kev": fetch_kev,
    "urlhaus": fetch_urlhaus,
    "openphish": fetch_openphish,
    "feodo": fetch_feodo,
    "blocklistde": fetch_blocklistde,
    "et_compromised": fetch_et_compromised,
    "cins": fetch_cins,
    "phishing_army": fetch_phishing_army,
    "otx": fetch_otx,
    "abuseipdb": fetch_abuseipdb,
    "threatfox": fetch_threatfox,
    "taxii": fetch_taxii,
    "demo": fetch_demo,
}


def _alert_payload(alert) -> dict:
    return {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "score": alert.score,
        "status": alert.status,
        "indicator_id": alert.indicator_id,
        "created_at": iso(alert.created_at),
    }


def send_outbound_alert(payload: dict) -> None:
    if not settings.outbound_webhook_url or not settings.outbound_webhook_secret:
        return
    try:
        body = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(
            settings.outbound_webhook_secret.encode(), body.encode(), hashlib.sha256
        ).hexdigest()
        validate_outbound_url(settings.outbound_webhook_url)
        with httpx.Client(timeout=8, follow_redirects=False) as client:
            client.post(
                settings.outbound_webhook_url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-ThreatLens-Signature": signature,
                    **UA,
                },
            )
    except Exception:
        return


def run_feed(feed_id: str) -> dict[str, Any]:
    alerts_out: list[dict] = []
    high_severity_ids: set[str] = set()
    with session_scope() as db:
        feed = db.get(Feed, feed_id)
        if feed is None:
            return {"ok": False, "error": "Feed not found"}
        feed.last_run_at = utcnow()
        feed.last_status = "running"
        feed.last_error = None
        db.commit()

    try:
        with session_scope() as db:
            feed = db.get(Feed, feed_id)
            fetcher = FETCHERS.get(feed.kind)
            if fetcher is None:
                raise ValueError(f"Unsupported feed type: {feed.kind}")
            records = fetcher(feed)
            source = feed.name
            processed = 0
            created = 0
            for record in records[:500]:
                record["source"] = source
                indicator, was_created = upsert_indicator(
                    db,
                    value=record["value"],
                    kind=record.get("type"),
                    source=source,
                    feed_id=feed.id,
                    confidence=int(record.get("confidence", 60)),
                    reliability=float(record.get("reliability", RELIABILITY.get(feed.kind, 0.7))),
                    tlp=record.get("tlp", "amber"),
                    tags=record.get("tags"),
                    attack_ids=record.get("attack_ids"),
                    notes=record.get("notes"),
                    raw_ref=record.get("raw_ref"),
                    first_seen=record.get("first_seen"),
                    last_seen=record.get("last_seen"),
                    kev=bool(record.get("kev", False)),
                    malicious_ratio=record.get("malicious_ratio"),
                )
                if indicator is None:
                    continue
                processed += 1
                created += 1 if was_created else 0
                events = correlate_indicator(db, indicator)
                if indicator.status == "active" and indicator.severity_score >= 60:
                    high_severity_ids.add(indicator.id)
                new_alerts = create_alerts_for_indicator(db, indicator, events)
                alerts_out.extend(_alert_payload(alert) for alert in new_alerts)
                if processed % 40 == 0:
                    db.commit()
            feed = db.get(Feed, feed_id)
            feed.last_status = "success"
            feed.last_error = None
            feed.indicator_count = processed
            feed.last_run_at = utcnow()
            record_audit(
                db,
                "feed.run",
                actor=SystemActor,
                object_type="feed",
                object_id=feed.id,
                detail={
                    "feed": feed.name,
                    "kind": feed.kind,
                    "processed": processed,
                    "created": created,
                },
            )
            db.commit()
        for index, alert in enumerate(alerts_out):
            manager.publish("alerts.stream", alert)
            if index < 20 and alert["severity"] in {"critical", "high"}:
                send_outbound_alert(alert)
        for indicator_id in high_severity_ids:
            manager.publish("indicators.high_severity", {"id": indicator_id})
        manager.publish("system.health", {"feed_id": feed_id, "status": "success"})
        return {"ok": True, "processed": processed, "created": created, "alerts": len(alerts_out)}
    except Exception as exc:
        with session_scope() as db:
            feed = db.get(Feed, feed_id)
            if feed:
                feed.last_status = "error"
                feed.last_error = str(exc)[:500]
                feed.last_run_at = utcnow()
                record_audit(
                    db,
                    "feed.error",
                    actor=SystemActor,
                    object_type="feed",
                    object_id=feed.id,
                    detail={"feed": feed.name, "error": str(exc)[:300]},
                )
                db.commit()
        manager.publish("system.health", {"feed_id": feed_id, "status": "error"})
        return {"ok": False, "error": str(exc)[:300]}


def expire_indicators(ttl_days: int = 90) -> int:
    with session_scope() as db:
        cutoff = utcnow() - timedelta(days=ttl_days)
        indicators = db.execute(
            select(Indicator).where(
                Indicator.status == "active", Indicator.last_seen < cutoff
            )
        ).scalars().all()
        for indicator in indicators:
            indicator.status = "expired"
            indicator.severity_score = 0
            indicator.updated_at = utcnow()
        if indicators:
            record_audit(
                db,
                "indicator.expire",
                actor=SystemActor,
                object_type="indicator",
                detail={"count": len(indicators), "ttl_days": ttl_days},
            )
        db.commit()
        return len(indicators)

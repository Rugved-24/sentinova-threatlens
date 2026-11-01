"""Deterministic, clearly-labelled synthetic intelligence for offline demos.

All network indicators use reserved documentation ranges (TEST-NET-1/2/3 and
example.com/.org/.net). No real host is accused. Public CVE identifiers are
reference data with explicit demo context.
"""

from __future__ import annotations

import hashlib
import random
from datetime import timedelta
from typing import Any

from .utils import utcnow

GEO_POINTS = [
    ("US", "United States", 38.9, -77.0),
    ("DE", "Germany", 52.5, 13.4),
    ("NL", "Netherlands", 52.1, 4.3),
    ("SG", "Singapore", 1.35, 103.8),
    ("IN", "India", 19.1, 72.9),
    ("BR", "Brazil", -23.5, -46.6),
    ("RU", "Russia", 55.7, 37.6),
    ("CN", "China", 39.9, 116.4),
    ("GB", "United Kingdom", 51.5, -0.12),
    ("JP", "Japan", 35.7, 139.7),
]

CATEGORIES: dict[str, dict[str, Any]] = {
    "c2": {"tags": ["c2", "botnet"], "attack": ["T1071", "T1095"], "weight": 4},
    "phishing": {"tags": ["phishing", "credential-harvest"], "attack": ["T1566", "T1078"], "weight": 3},
    "loader": {"tags": ["loader", "malware"], "attack": ["T1105", "T1059"], "weight": 3},
    "ransomware": {"tags": ["ransomware", "impact"], "attack": ["T1486", "T1490"], "weight": 2},
    "exploit": {"tags": ["exploit", "vulnerability"], "attack": ["T1190", "T1203"], "weight": 2},
    "exfil": {"tags": ["exfiltration"], "attack": ["T1041", "T1567"], "weight": 1},
    "recon": {"tags": ["scanning", "reconnaissance"], "attack": ["T1595", "T1046"], "weight": 1},
}

DEMO_CVES = [
    ("CVE-2021-44228", "Apache Log4j2 remote code execution via JNDI lookup."),
    ("CVE-2023-34362", "Progress MOVEit Transfer SQL injection leading to remote code execution."),
    ("CVE-2024-3400", "Palo Alto Networks GlobalProtect command injection."),
    ("CVE-2023-4966", "Citrix NetScaler sensitive information disclosure."),
    ("CVE-2022-22965", "Spring Framework data binding remote code execution."),
    ("CVE-2024-23897", "Jenkins CLI arbitrary file read."),
    ("CVE-2023-3519", "Citrix ADC remote code execution."),
    ("CVE-2021-34527", "Windows Print Spooler remote code execution."),
]

HOST_PREFIX = ["WKS", "SRV", "FIN", "HR", "DEV", "EDGE"]
USERS = ["a.patel", "j.silva", "m.chen", "s.khan", "l.mueller", "d.okafor", "r.adeyemi"]


def _geo(rng: random.Random) -> dict[str, Any]:
    code, name, lat, lon = rng.choice(GEO_POINTS)
    return {
        "country_code": code,
        "country_name": name,
        "latitude": round(lat + rng.uniform(-1.8, 1.8), 3),
        "longitude": round(lon + rng.uniform(-1.8, 1.8), 3),
        "city": None,
        "asn": f"AS{rng.randint(10000, 65000)}",
        "org": f"Demo Hosting {rng.randint(1, 99)}",
        "simulated": True,
    }


def generate_demo_records(count: int = 64, days: int = 30, seed: int = 20260701) -> list[dict]:
    rng = random.Random(seed)
    now = utcnow()
    categories = list(CATEGORIES)
    records: list[dict] = []
    for index in range(count):
        category = categories[index % len(categories)]
        meta = CATEGORIES[category]
        elite = index % 13 == 0
        first_seen = now - timedelta(days=rng.randint(0, days), hours=rng.randint(0, 23))
        last_seen = min(now, first_seen + timedelta(days=rng.randint(0, 4), hours=rng.randint(0, 12)))
        if elite:
            last_seen = now - timedelta(hours=rng.randint(0, 18))
        confidence = 97 if elite else rng.randint(55, 96)
        reliability = 0.98 if elite else round(rng.uniform(0.55, 0.92), 2)
        tlp = rng.choices(["clear", "green", "amber", "red"], weights=[1, 2, 5, 1])[0]
        kind_roll = index % 10
        if kind_roll < 4:
            value = f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(10, 250)}"
            kind = "ip"
        elif kind_roll < 6:
            host = rng.choice(["example.com", "example.org", "example.net"])
            label = rng.choice(["c2-node", "phish-portal", "cdn-sync", "update-gateway"])
            value = f"{label}-{index}.{host}"
            kind = "domain"
        elif kind_roll < 8:
            label = rng.choice(["c2-node", "phish-portal", "payload-drop"])
            domain = f"{label}-{index}.example.{rng.choice(['com', 'org', 'net'])}"
            path = rng.choice(["gate.php", "login", "update.bin", "api/v2/sync"])
            value = f"https://{domain}/{path}"
            kind = "url"
        elif kind_roll == 8:
            value = hashlib.sha256(f"threatlens-demo-{index}".encode()).hexdigest()
            kind = "hash_sha256"
        elif kind_roll == 9 and index % 20 == 9:
            cve, description = rng.choice(DEMO_CVES)
            value = cve
            kind = "cve"
            records.append(
                {
                    "value": value,
                    "type": kind,
                    "source": "CISA KEV (reference)",
                    "confidence": 98,
                    "reliability": 1.0,
                    "tlp": "clear",
                    "tags": ["cisa-kev", "known-exploited", "public-reference"],
                    "attack_ids": ["T1190"],
                    "notes": (
                        f"{description} Public KEV reference included in the synthetic "
                        "demo dataset; no customer exposure is asserted."
                    ),
                    "first_seen": first_seen,
                    "last_seen": now - timedelta(hours=rng.randint(0, 36)),
                    "kev": True,
                    "malicious_ratio": 0.95,
                    "geo": _geo(rng),
                    "category": "exploit",
                }
            )
            continue
        else:
            value = f"actor-{index}@example.com"
            kind = "email"

        geo = _geo(rng) if kind == "ip" else _geo(rng)
        records.append(
            {
                "value": value,
                "type": kind,
                "source": "ThreatLens Demo Feed",
                "confidence": confidence,
                "reliability": reliability,
                "tlp": tlp,
                "tags": ["demo", "synthetic", *meta["tags"]],
                "attack_ids": meta["attack"],
                "notes": (
                    "Synthetic demonstration record using reserved documentation "
                    "addresses. Not a real-world threat attribution."
                ),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "kev": False,
                "malicious_ratio": 0.98 if elite else round(rng.uniform(0.45, 0.95), 2),
                "geo": geo,
                "category": category,
            }
        )
        if index % 9 == 0:
            records[-1]["source"] = "Open Source Correlation"
            records[-1]["reliability"] = 0.78
            records[-1]["confidence"] = max(50, confidence - 12)
        elif index % 11 == 0:
            records[-1]["source"] = "Internal Sensor Telemetry"
            records[-1]["reliability"] = 0.85
            records[-1]["confidence"] = max(55, confidence - 5)
    return records


def generate_relationships(records: list[dict]) -> list[tuple[str, str, str, str]]:
    """Return (source_value, target_value, target_type, relation_type) edges."""
    by_type: dict[str, list[str]] = {}
    for record in records:
        by_type.setdefault(record["type"], []).append(record["value"])
    edges: list[tuple[str, str, str, str]] = []
    ips = by_type.get("ip", [])
    domains = by_type.get("domain", [])
    urls = by_type.get("url", [])
    hashes = by_type.get("hash_sha256", [])
    for index, url in enumerate(urls[:8]):
        if domains:
            edges.append((url, domains[index % len(domains)], "domain", "communicates-with"))
    for index, domain in enumerate(domains[:8]):
        if ips:
            edges.append((domain, ips[index % len(ips)], "ip", "resolves-to"))
    for index, hash_value in enumerate(hashes[:8]):
        target = domains[index % len(domains)] if domains else (ips[0] if ips else None)
        if target:
            edges.append((hash_value, target, "domain" if domains else "ip", "delivered-from"))
    for index in range(min(5, len(urls), len(hashes))):
        edges.append((hashes[index], urls[index], "url", "served-at"))
    return edges


def generate_security_events(records: list[dict], seed: int = 20260702) -> list[dict]:
    rng = random.Random(seed)
    now = utcnow()
    ips = [r["value"] for r in records if r["type"] == "ip"]
    domains = [r["value"] for r in records if r["type"] == "domain"]
    hashes = [r["value"] for r in records if r["type"].startswith("hash_")]
    event_types = ["dns_query", "proxy_connection", "edr_detection", "auth_anomaly", "firewall_alert"]
    events: list[dict] = []
    for index in range(22):
        event_time = now - timedelta(days=rng.randint(0, 13), hours=rng.randint(0, 23))
        host = f"{rng.choice(HOST_PREFIX)}-{rng.randint(100, 999)}"
        user = rng.choice(USERS)
        target_country = rng.choice([point[0] for point in GEO_POINTS])
        event_type = event_types[index % len(event_types)]
        event = {
            "event_time": event_time,
            "event_type": event_type,
            "host": host,
            "user_name": user,
            "country": target_country,
            "raw": {"sensor": "demo-telemetry", "synthetic": True},
        }
        if index < 10 and ips:
            event["src_ip"] = ips[index % len(ips)]
            event["dst_ip"] = f"10.20.{rng.randint(1, 20)}.{rng.randint(2, 250)}"
        elif domains:
            event["domain"] = domains[index % len(domains)]
            event["src_ip"] = f"10.20.{rng.randint(1, 20)}.{rng.randint(2, 250)}"
        elif hashes:
            event["file_hash"] = hashes[index % len(hashes)]
        events.append(event)
    return events

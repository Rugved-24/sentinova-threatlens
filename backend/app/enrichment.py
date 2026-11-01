from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .ingest import recompute_indicator
from .models import Enrichment, Indicator, IndicatorSource
from .utils import clamp, utcnow

settings = get_settings()
UA = {"User-Agent": "ThreatLens/1.0 (CTI internship project)"}


def _cached(db: Session, indicator_id: str, kind: str) -> Enrichment | None:
    return db.execute(
        select(Enrichment)
        .where(
            Enrichment.indicator_id == indicator_id,
            Enrichment.kind == kind,
            Enrichment.expires_at > utcnow(),
        )
        .order_by(Enrichment.fetched_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _store(
    db: Session,
    indicator: Indicator,
    *,
    provider: str,
    kind: str,
    verdict: str | None,
    score: int | None,
    data: dict[str, Any],
    simulated: bool,
    ttl_hours: int,
) -> Enrichment:
    row = Enrichment(
        indicator_id=indicator.id,
        provider=provider,
        kind=kind,
        verdict=verdict,
        score=score,
        data=data,
        simulated=simulated,
        expires_at=utcnow() + timedelta(hours=ttl_hours),
    )
    db.add(row)
    return row


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _geo(db: Session, indicator: Indicator) -> dict[str, Any] | None:
    if indicator.type != "ip" or not _public_ip(indicator.value):
        return None
    cached = _cached(db, indicator.id, "geo")
    if cached:
        return cached.data
    try:
        with httpx.Client(timeout=8, headers=UA, follow_redirects=False) as client:
            response = client.get(f"https://ipapi.co/{indicator.value}/json/")
            response.raise_for_status()
            data = response.json()
        geo = {
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "city": data.get("city"),
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "simulated": False,
        }
        _store(
            db, indicator, provider="ipapi.co", kind="geo", verdict=None, score=None,
            data=geo, simulated=False, ttl_hours=24 * 7,
        )
        if geo.get("country_code"):
            indicator.country = geo["country_code"]
        if geo.get("asn") or geo.get("org"):
            indicator.asn = (geo.get("asn") or geo.get("org") or "")[:160]
        indicator.geo = geo
        return geo
    except Exception:
        return None


def _local_verdict(db: Session, indicator: Indicator) -> dict[str, Any]:
    sources = db.execute(
        select(IndicatorSource.source_name).where(IndicatorSource.indicator_id == indicator.id)
    ).scalars().all()
    base = 0.45 + min(0.25, 0.05 * max(0, len(sources) - 1))
    if indicator.kev:
        base = max(base, 0.92)
    if indicator.internal_sightings > 0:
        base = min(0.98, base + 0.1)
    if indicator.status == "whitelisted":
        base = 0.0
    ratio = round(clamp(base, 0.0, 1.0), 2)
    return {
        "malicious_ratio": ratio,
        "verdict": "potentially-malicious" if ratio >= 0.5 else "unknown",
        "provider": "local-heuristic",
        "simulated": True,
        "note": (
            "Derived from feed provenance and internal sightings. Configure "
            "AbuseIPDB or VirusTotal keys for independent third-party verdicts."
        ),
        "sources": sources,
    }


def _abuseipdb(indicator: Indicator) -> dict[str, Any] | None:
    if not settings.abuseipdb_api_key:
        return None
    try:
        with httpx.Client(timeout=10, headers=UA, follow_redirects=False) as client:
            response = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator.value, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json().get("data", {})
        score = int(payload.get("abuseConfidenceScore", 0))
        return {
            "malicious_ratio": score / 100.0,
            "verdict": "malicious" if score >= 50 else "low-risk",
            "provider": "AbuseIPDB",
            "simulated": False,
            "abuse_confidence": score,
            "total_reports": payload.get("totalReports", 0),
            "usage_type": payload.get("usageType"),
            "isp": payload.get("isp"),
            "country": payload.get("countryCode"),
            "last_reported": payload.get("lastReportedAt"),
        }
    except Exception:
        return None


def _virustotal(indicator: Indicator) -> dict[str, Any] | None:
    if not settings.virustotal_api_key:
        return None
    endpoint = None
    if indicator.type.startswith("hash_"):
        endpoint = f"https://www.virustotal.com/api/v3/files/{indicator.value}"
    elif indicator.type == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{indicator.value}"
    elif indicator.type == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator.value}"
    if endpoint is None:
        return None
    try:
        with httpx.Client(timeout=12, headers=UA, follow_redirects=False) as client:
            response = client.get(endpoint, headers={"x-apikey": settings.virustotal_api_key})
            response.raise_for_status()
            attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = malicious + suspicious + int(stats.get("harmless", 0)) + int(
            stats.get("undetected", 0)
        )
        ratio = (malicious + suspicious * 0.5) / total if total else 0.0
        result = {
            "malicious_ratio": round(ratio, 3),
            "verdict": "malicious" if malicious >= 3 else "unknown",
            "provider": "VirusTotal",
            "simulated": False,
            "engines_malicious": malicious,
            "engines_suspicious": suspicious,
            "engines_total": total,
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags", [])[:10],
        }
        if indicator.type == "domain" and attributes.get("creation_date"):
            created = datetime.fromtimestamp(int(attributes["creation_date"]), UTC)
            age_days = max(0, (datetime.now(UTC) - created).days)
            result.update(
                creation_date=created.isoformat(),
                domain_age_days=age_days,
                newly_registered=age_days < 30,
            )
        return result
    except Exception:
        return None


def _aggregate_verdicts(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not results:
        return None
    ratios = [float(item.get("malicious_ratio", 0) or 0) for item in results]
    ratio = round(sum(ratios) / len(ratios), 3)
    providers = [str(item.get("provider", "unknown")) for item in results]
    return {
        "malicious_ratio": ratio,
        "verdict": (
            "malicious"
            if any(item.get("verdict") == "malicious" for item in results) or ratio >= 0.5
            else "low-risk"
        ),
        "provider": " + ".join(providers),
        "simulated": False,
        "provider_count": len(results),
        "providers": results,
        "domain_age_days": next((item["domain_age_days"] for item in results if "domain_age_days" in item), None),
        "newly_registered": any(bool(item.get("newly_registered")) for item in results),
    }


def enrich_indicator(db: Session, indicator: Indicator, *, force: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"indicator_id": indicator.id, "actions": []}
    geo = _geo(db, indicator)
    if geo:
        result["geo"] = geo
        result["actions"].append("geo")

    cached_verdict = None if force else _cached(db, indicator.id, "verdict")
    simulated = True
    if cached_verdict:
        verdict_data = cached_verdict.data
        simulated = cached_verdict.simulated
        result["actions"].append("verdict-cache")
    else:
        live_results = []
        if indicator.type == "ip":
            live_results = [item for item in (_abuseipdb(indicator), _virustotal(indicator)) if item]
        elif indicator.type in {"domain", "hash_md5", "hash_sha1", "hash_sha256"}:
            live_results = [item for item in (_virustotal(indicator),) if item]
        verdict_data = _aggregate_verdicts(live_results)
        if verdict_data is None:
            verdict_data = _local_verdict(db, indicator)
            simulated = True
        else:
            simulated = bool(verdict_data.pop("simulated", False))
        _store(
            db,
            indicator,
            provider=str(verdict_data.get("provider", "local-heuristic")),
            kind="verdict",
            verdict=str(verdict_data.get("verdict", "unknown")),
            score=int(round(float(verdict_data.get("malicious_ratio", 0)) * 100)),
            data=verdict_data,
            simulated=simulated,
            ttl_hours=6 if not simulated else 24,
        )
        result["actions"].append("verdict-fetch")

    ratio = float(verdict_data.get("malicious_ratio", 0) or 0)
    indicator.malicious_ratio = max(indicator.malicious_ratio, clamp(ratio, 0, 1))
    indicator.updated_at = utcnow()
    db.add(indicator)
    recompute_indicator(db, indicator)
    result["verdict"] = verdict_data.get("verdict", "unknown")
    result["malicious_ratio"] = round(indicator.malicious_ratio, 2)
    result["simulated"] = simulated
    result["score"] = indicator.severity_score
    return result

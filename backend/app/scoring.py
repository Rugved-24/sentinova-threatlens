"""Transparent, reproducible severity scoring.

The model is intentionally additive and bounded to 100 points:

  source reputation .... 0-30  weighted source confidence x feed reliability
  recency .............. 0-20  14-day half-life decay from last seen
  malicious verdict .... 0-25  third-party or source-derived malicious ratio
  internal sightings ... 0-15  5 * log2(1 + sightings)
  exploitation ......... 0-10  CISA KEV bonus, or ATT&CK mapping weight

Every contribution is persisted in indicators.score_breakdown so an analyst can
explain a score without re-running the engine.
"""

from __future__ import annotations

import math
from datetime import datetime

from .utils import clamp, utcnow


def compute_score(
    *,
    source_confidence: int,
    last_seen: datetime,
    source_reliability: float = 1.0,
    internal_sightings: int = 0,
    malicious_ratio: float = 0.0,
    kev: bool = False,
    attack_count: int = 0,
    status: str = "active",
) -> dict:
    confidence = int(clamp(source_confidence, 0, 100))
    reliability = clamp(source_reliability, 0.0, 1.0)
    sightings = max(0, int(internal_sightings))
    ratio = clamp(malicious_ratio, 0.0, 1.0)
    techniques = max(0, int(attack_count))

    if status in {"whitelisted", "expired"}:
        return {
            "score": 0,
            "confidence": confidence,
            "components": {
                "source": 0.0, "recency": 0.0, "verdict": 0.0,
                "sightings": 0.0, "exploitation": 0.0,
            },
            "reasons": [f"Status '{status}' suppresses scoring"],
            "model": "threatlens-v1",
        }

    age_days = max(0.0, (utcnow() - last_seen).total_seconds() / 86400)
    recency_factor = 0.5 ** (age_days / 14.0)
    source_component = 30.0 * (confidence / 100.0) * reliability
    recency_component = 20.0 * recency_factor
    verdict_component = 25.0 * ratio
    sightings_component = min(15.0, 5.0 * math.log2(1 + sightings))
    exploitation_component = 10.0 if kev else min(6.0, 1.5 * techniques)

    total = (
        source_component
        + recency_component
        + verdict_component
        + sightings_component
        + exploitation_component
    )
    score = int(round(clamp(total, 0.0, 100.0)))
    component_map = {
        "source": round(source_component, 2),
        "recency": round(recency_component, 2),
        "verdict": round(verdict_component, 2),
        "sightings": round(sightings_component, 2),
        "exploitation": round(exploitation_component, 2),
    }
    reasons = [
        f"Source confidence {confidence}% at {round(reliability * 100)}% reliability",
        f"Last seen {round(age_days, 1)} days ago (14-day half-life)",
        f"Malicious verdict ratio {round(ratio * 100)}%",
        f"{sightings} internal sighting(s)",
        "Listed in CISA KEV" if kev else f"{techniques} ATT&CK technique mapping(s)",
    ]
    return {
        "score": score,
        "confidence": int(round(confidence * (0.55 + 0.45 * reliability))),
        "components": component_map,
        "reasons": reasons,
        "model": "threatlens-v1",
        "age_days": round(age_days, 2),
    }


def severity_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"

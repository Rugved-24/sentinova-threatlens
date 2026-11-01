from __future__ import annotations

from datetime import timedelta

import pytest
from app.scoring import compute_score, severity_for_score
from app.utils import utcnow


def score(**overrides):
    base = {
        "source_confidence": 100,
        "source_reliability": 1.0,
        "last_seen": utcnow(),
        "internal_sightings": 0,
        "malicious_ratio": 0.0,
        "kev": False,
        "attack_count": 0,
        "status": "active",
    }
    base.update(overrides)
    return compute_score(**base)


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, 50),
        ({"malicious_ratio": 1.0}, 75),
        ({"internal_sightings": 7}, 65),
        ({"kev": True}, 60),
        ({"attack_count": 2}, 53),
        ({"source_confidence": 50, "source_reliability": 0.8}, 32),
        ({"last_seen": utcnow() - timedelta(days=28)}, 35),
        ({"status": "expired"}, 0),
        ({"status": "whitelisted"}, 0),
    ],
)
def test_score_table(overrides, expected):
    assert score(**overrides)["score"] == expected


def test_score_is_bounded_and_explained():
    result = score(
        source_confidence=100,
        source_reliability=1.0,
        internal_sightings=20,
        malicious_ratio=1.0,
        kev=True,
    )
    assert result["score"] == 100
    assert set(result["components"]) == {
        "source",
        "recency",
        "verdict",
        "sightings",
        "exploitation",
    }
    assert len(result["reasons"]) == 5
    assert result["model"] == "threatlens-v1"


def test_confidence_blends_reliability():
    assert score(source_reliability=0.0)["confidence"] == 55
    assert score(source_reliability=1.0)["confidence"] == 100


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (100, "critical"),
        (80, "critical"),
        (79, "high"),
        (60, "high"),
        (59, "medium"),
        (40, "medium"),
        (39, "low"),
        (0, "low"),
    ],
)
def test_severity_bands(value, expected):
    assert severity_for_score(value) == expected

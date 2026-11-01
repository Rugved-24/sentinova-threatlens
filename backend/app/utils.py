from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

SECRET_KEYS = re.compile(r"(password|token|secret|authorization|api[_-]?key|otp|mfa)", re.I)


def utcnow() -> datetime:
    """Naive UTC timestamp, stored consistently in SQLite."""
    return datetime.now(UTC).replace(tzinfo=None)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def new_id() -> str:
    return str(uuid.uuid4())


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def redact(value: Any) -> Any:
    """Recursively strip secret-looking keys from logs and audit payloads."""
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if SECRET_KEYS.search(str(key)) else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


TLP_ORDER = {"clear": 0, "green": 1, "amber": 2, "red": 3}


def most_restrictive_tlp_value(values: list[str]) -> str:
    valid = [value for value in values if value in TLP_ORDER]
    if not valid:
        return "amber"
    return max(valid, key=lambda value: TLP_ORDER[value])

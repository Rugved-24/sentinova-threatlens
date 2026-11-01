from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, Request, status

from .config import get_settings
from .utils import sha256

settings = get_settings()
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
ACCESS_COOKIE = "tl_refresh"

ROLES = {
    "admin",
    "engineer",
    "responder",
    "hunter",
    "analyst",
    "executive",
}

PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "view_dashboards", "search", "view_indicators", "edit_indicators", "tag_indicators",
        "enrich", "manage_alerts", "read_incidents", "manage_incidents", "create_hunts",
        "export", "generate_reports", "configure_feeds", "manage_users", "view_audit",
        "manage_rules",
    },
    "engineer": {
        "view_dashboards", "search", "view_indicators", "edit_indicators", "tag_indicators",
        "enrich", "read_incidents", "create_hunts", "export", "generate_reports",
        "configure_feeds", "view_audit", "manage_rules",
    },
    "responder": {
        "view_dashboards", "search", "view_indicators", "edit_indicators", "tag_indicators",
        "enrich", "manage_alerts", "read_incidents", "manage_incidents", "create_hunts",
        "export", "generate_reports", "view_audit", "manage_rules",
    },
    "hunter": {
        "view_dashboards", "search", "view_indicators", "tag_indicators", "enrich",
        "read_incidents", "create_hunts", "export", "generate_reports",
    },
    "analyst": {
        "view_dashboards", "search", "view_indicators", "edit_indicators", "tag_indicators",
        "enrich", "manage_alerts", "read_incidents", "manage_incidents", "create_hunts",
        "export", "generate_reports",
    },
    "executive": {"view_dashboards", "generate_reports"},
}

TLP_CLEARANCE = {
    "admin": {"clear", "green", "amber", "red"},
    "engineer": {"clear", "green", "amber", "red"},
    "responder": {"clear", "green", "amber", "red"},
    "hunter": {"clear", "green", "amber"},
    "analyst": {"clear", "green", "amber"},
    "executive": set(),
}


def allowed_tlps(role: str) -> set[str]:
    return TLP_CLEARANCE.get(role, set())


def can_view_tlp(role: str, tlp: str) -> bool:
    return tlp in TLP_CLEARANCE.get(role, set())


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


def require_permission(user, permission: str) -> None:
    if not has_permission(user.role, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "forbidden", "message": "Insufficient permissions"},
        )


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def password_policy_errors(password: str) -> list[str]:
    errors = []
    if len(password) < 12:
        errors.append("at least 12 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"\d", password):
        errors.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("a symbol")
    return errors


def create_access_token(user_id: str, role: str) -> tuple[str, int]:
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=settings.access_token_minutes)
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("="),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm="HS256")
    return token, settings.access_token_minutes * 60


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error_code": "token_expired", "message": "Access token expired"},
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error_code": "invalid_token", "message": "Invalid access token"},
        ) from exc
    if payload.get("type") != "access" or not payload.get("sub"):
        raise HTTPException(
            status_code=401,
            detail={"error_code": "invalid_token", "message": "Invalid access token"},
        )
    return payload


def new_refresh_token() -> tuple[str, str]:
    raw = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
    return raw, sha256(raw)


def refresh_cookie(response, raw: str) -> None:
    max_age = settings.refresh_token_days * 86400
    response.set_cookie(
        ACCESS_COOKIE,
        raw,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api/v1/auth",
    )


def clear_refresh_cookie(response) -> None:
    response.delete_cookie(
        ACCESS_COOKIE,
        path="/api/v1/auth",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _aes_key() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"threatlens-secrets-v1",
        info=b"aes-256-gcm",
    ).derive(settings.secret_key.encode("utf-8"))


def encrypt_secret(plaintext: str) -> str:
    nonce = os.urandom(12)
    payload = AESGCM(_aes_key()).encrypt(nonce, plaintext.encode("utf-8"), b"threatlens")
    return base64.urlsafe_b64encode(nonce + payload).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    try:
        data = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
        return AESGCM(_aes_key()).decrypt(data[:12], data[12:], b"threatlens").decode("utf-8")
    except Exception as exc:
        raise ValueError("Unable to decrypt secret") from exc


def encrypt_json(value: dict) -> str:
    return encrypt_secret(json.dumps(value, separators=(",", ":")))


def decrypt_json(ciphertext: str) -> dict:
    return json.loads(decrypt_secret(ciphertext))


PRIVATE_NETS = [
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::1/128",
        "fc00::/7", "fe80::/10", "ff00::/8",
    )
]
BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "instance-data"}


def validate_outbound_url(url: str) -> str:
    """Reject SSRF-prone destinations for admin-configured feed and webhook URLs."""
    if not url or len(url) > 2048:
        raise ValueError("URL is required and must be under 2048 characters")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in BLOCKED_HOSTS or host.endswith(".local") or host.endswith(".internal"):
        raise ValueError("Destination host is not permitted")
    try:
        addresses = {addr[4][0] for addr in socket.getaddrinfo(host, parsed.port or 443)}
    except OSError as exc:
        raise ValueError("Destination host could not be resolved") from exc
    for raw in addresses:
        ip = ipaddress.ip_address(raw.split("%")[0])
        if any(ip in network for network in PRIVATE_NETS) or not ip.is_global:
            raise ValueError("Destination resolves to a non-public address")
    return url


class RateLimiter:
    """Small in-process sliding window limiter; good for a single-node deployment."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._calls = 0

    def check(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, max(1, int(window_seconds - (now - bucket[0])))
            bucket.append(now)
            self._calls += 1
            if self._calls % 5000 == 0:
                for stale_key in [k for k, v in self._events.items() if not v or v[-1] < cutoff]:
                    self._events.pop(stale_key, None)
            return True, 0


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]

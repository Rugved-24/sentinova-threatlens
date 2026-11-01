from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
HASH_TYPES = {32: "hash_md5", 40: "hash_sha1", 64: "hash_sha256"}
INDICATOR_TYPES = {
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve",
}
TLP_VALUES = {"clear", "green", "amber", "red"}


def detect_type(raw: str) -> str | None:
    value = (raw or "").strip()
    if not value:
        return None
    if CVE_RE.match(value):
        return "cve"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value.strip("[]"))
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.match(value):
        return "email"
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) in HASH_TYPES:
        return HASH_TYPES[len(value)]
    if DOMAIN_RE.match(value.rstrip(".")):
        return "domain"
    return None


def canonicalize(raw: str, kind: str | None = None) -> tuple[str, str] | None:
    value = (raw or "").strip().strip("\"'")
    if not value or len(value) > 2048:
        return None
    kind = kind or detect_type(value)
    if kind not in INDICATOR_TYPES:
        return None
    try:
        if kind == "ip":
            return ipaddress.ip_address(value.strip("[]")).compressed, kind
        if kind in {"hash_md5", "hash_sha1", "hash_sha256"}:
            value = value.lower()
            if len(value) != int([k for k, v in HASH_TYPES.items() if v == kind][0]):
                return None
            return (value, kind) if re.fullmatch(r"[0-9a-f]+", value) else None
        if kind == "cve":
            value = value.upper()
            return (value, kind) if CVE_RE.match(value) else None
        if kind == "email":
            value = value.lower()
            return (value, kind) if EMAIL_RE.match(value) else None
        if kind == "domain":
            value = value.lower().rstrip(".")
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError:
                return None
            return (value, kind) if DOMAIN_RE.match(value) else None
        if kind == "url":
            parts = urlsplit(value)
            scheme = parts.scheme.lower()
            if scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
                return None
            raw_host = parts.hostname.lower().rstrip(".")
            try:
                address = ipaddress.ip_address(raw_host)
                host = f"[{address.compressed}]" if address.version == 6 else address.compressed
            except ValueError:
                host = raw_host.encode("idna").decode("ascii")
                if not DOMAIN_RE.fullmatch(host):
                    return None
            port = parts.port
            default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            netloc = host if port is None or default_port else f"{host}:{port}"
            path = parts.path or "/"
            return urlunsplit((scheme, netloc, path, parts.query, "")), kind
    except (ValueError, UnicodeError):
        return None
    return None


def normalize_tlp(value: str | None) -> str:
    normalized = (value or "amber").lower().strip()
    return normalized if normalized in TLP_VALUES else "amber"


def parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract simple observable values from a STIX 2.1 indicator pattern."""
    found: list[tuple[str, str]] = []
    paths = {
        "ipv4-addr:value": "ip",
        "ipv6-addr:value": "ip",
        "domain-name:value": "domain",
        "url:value": "url",
        "email-addr:value": "email",
        "file:hashes.'MD5'": "hash_md5",
        "file:hashes.MD5": "hash_md5",
        "file:hashes.'SHA-1'": "hash_sha1",
        "file:hashes.'SHA-256'": "hash_sha256",
        "file:hashes.SHA256": "hash_sha256",
        "vulnerability:name": "cve",
    }
    for path, kind in paths.items():
        escaped = re.escape(path)
        for match in re.finditer(rf"{escaped}\s*=\s*'([^']+)'", pattern, re.I):
            result = canonicalize(match.group(1), kind)
            if result:
                found.append(result)
    return found


def extract_indicators_from_text(text: str) -> list[tuple[str, str]]:
    tokens = re.findall(r"https?://[^\s<>\"]+|\bCVE-\d{4}-\d{4,7}\b|\b[0-9a-fA-F]{64}\b", text)
    results = []
    for token in tokens:
        result = canonicalize(token)
        if result:
            results.append(result)
    return results

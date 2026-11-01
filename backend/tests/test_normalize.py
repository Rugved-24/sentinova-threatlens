from __future__ import annotations

import pytest
from app.normalize import canonicalize, detect_type, normalize_tlp, parse_stix_pattern


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        ("192.0.2.10", "ip"),
        ("2001:db8::1", "ip"),
        ("Example.COM.", "domain"),
        ("https://Example.com/login", "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash_sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb924" + "27ae41e4649b934ca495991b7852b855", "hash_sha256"),
        ("Analyst@Example.com", "email"),
        ("cve-2021-44228", "cve"),
    ],
)
def test_detection(raw, kind):
    assert detect_type(raw) == kind


def test_canonicalization():
    assert canonicalize("HTTPS://Example.COM:443/login?x=1#frag") == (
        "https://example.com/login?x=1",
        "url",
    )
    assert canonicalize("CVE-2021-44228") == ("CVE-2021-44228", "cve")
    assert canonicalize("Analyst@Example.com") == ("analyst@example.com", "email")
    assert canonicalize("2001:0db8::0001") == ("2001:db8::1", "ip")
    assert canonicalize("D41D8CD98F00B204E9800998ECF8427E", "hash_md5") == (
        "d41d8cd98f00b204e9800998ecf8427e",
        "hash_md5",
    )


@pytest.mark.parametrize(
    "raw",
    ["", "not an indicator", "http://", "CVE-21-1", "999.999.999.999", "a" * 2049],
)
def test_invalid_values(raw):
    assert canonicalize(raw) is None


def test_tlp_normalization():
    assert normalize_tlp("RED") == "red"
    assert normalize_tlp(None) == "amber"
    assert normalize_tlp("purple") == "amber"


def test_stix_pattern_parsing():
    pattern = (
        "[ipv4-addr:value = '198.51.100.4'] OR "
        "[domain-name:value = 'c2.example.org'] OR "
        "[file:hashes.'SHA-256' = "
        "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
    )
    assert parse_stix_pattern(pattern) == [
        ("198.51.100.4", "ip"),
        ("c2.example.org", "domain"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash_sha256"),
    ]

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from app.models import Indicator, IndicatorRelationship, IndicatorSource
from app.normalize import canonicalize, detect_type
from app.reporting import TLP_MARKINGS, _pattern, build_stix_bundle
from app.utils import utcnow


@pytest.mark.parametrize("kind,length", [("hash_md5", 32), ("hash_sha1", 40), ("hash_sha256", 64)])
def test_explicit_hash_types_require_hexadecimal(kind, length):
    assert canonicalize("f" * length, kind) == ("f" * length, kind)
    assert canonicalize("g" * length, kind) is None
    assert canonicalize("-" * length, kind) is None
    assert detect_type("g" * length) is None


@pytest.mark.parametrize(("raw", "expected"), [
    ("http://Example.com:80/path", "http://example.com/path"),
    ("https://Example.com:443/path", "https://example.com/path"),
    ("http://Example.com:443/path", "http://example.com:443/path"),
    ("https://Example.com:80/path", "https://example.com:80/path"),
    ("https://[2001:0db8::1]:443/a", "https://[2001:db8::1]/a"),
    ("http://[2001:db8::1]:443/a", "http://[2001:db8::1]:443/a"),
    ("https://BÜCHER.example/path#fragment", "https://xn--bcher-kva.example/path"),
])
def test_url_canonicalization_preserves_semantics(raw, expected):
    assert canonicalize(raw, "url") == (expected, "url")


@pytest.mark.parametrize("raw", [
    "https://user@example.com/path",
    "https://user:secret@example.com/path",
    "https://bad_host.example/path",
    "https://[2001:db8::1",
    "https://example.com:70000/path",
])
def test_url_canonicalization_rejects_ambiguous_or_invalid_authority(raw):
    assert canonicalize(raw, "url") is None


def new_indicator(db, value, kind, tlp):
    now = utcnow()
    item = Indicator(
        value=value, type=kind, tlp=tlp, confidence=80, severity_score=75,
        first_seen=now, last_seen=now, created_at=now, updated_at=now,
    )
    db.add(item)
    db.flush()
    return item


def validate_stix_shape(bundle):
    assert set(bundle) == {"type", "id", "objects"}
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    UUID(bundle["id"].split("--", 1)[1])
    ids = {item["id"] for item in bundle["objects"]}
    for item in bundle["objects"]:
        UUID(item["id"].split("--", 1)[1])
        assert item["spec_version"] == "2.1"
        assert item["id"].startswith(item["type"] + "--")
        assert item["created"] <= item["modified"]
        assert item["object_marking_refs"][0] in TLP_MARKINGS.values()
        if item["type"] == "indicator":
            assert item["pattern_type"] == "stix"
            assert item["pattern_version"] == "2.1"
            assert item["valid_from"] < item["valid_until"]
        elif item["type"] == "vulnerability":
            assert "pattern" not in item
            assert item["external_references"] == [{"source_name": "cve", "external_id": item["name"]}]
        elif item["type"] == "relationship":
            assert item["source_ref"] in ids
            assert item["target_ref"] in ids
        else:
            pytest.fail(f"Unexpected STIX object type: {item['type']}")


def test_stix_export_uses_vulnerability_objects_tlp_2_markings_and_stable_ids(db):
    suffix = uuid4().hex
    clear = new_indicator(db, f"2001:db8:{suffix[:4]}::{int(suffix[4:8], 16)}", "ip", "clear")
    green = new_indicator(db, f"{suffix}.example", "domain", "green")
    amber = new_indicator(db, f"CVE-2099-{int(suffix[:8], 16) % 10_000_000:07d}", "cve", "amber")
    red = new_indicator(db, suffix * 2, "hash_sha256", "red")
    db.add(IndicatorSource(indicator_id=green.id, source_name="Test source"))
    edge = IndicatorRelationship(source_id=green.id, target_id=amber.id, relation_type="related-to", confidence=90)
    db.add(edge)
    db.commit()

    bundle = build_stix_bundle(db, [clear, green, amber, red])
    validate_stix_shape(bundle)
    assert not any(item["type"] == "marking-definition" for item in bundle["objects"])
    exported = {item["name"]: item for item in bundle["objects"] if item["type"] != "relationship"}
    assert exported[amber.value]["type"] == "vulnerability"
    assert exported[f"IP {clear.value}"]["object_marking_refs"] == [TLP_MARKINGS["clear"]]
    assert exported[f"DOMAIN {green.value}"]["x_threatlens_sources"] == ["Test source"]
    assert exported[amber.value]["object_marking_refs"] == [TLP_MARKINGS["amber"]]
    assert exported[f"HASH_SHA256 {red.value}"]["object_marking_refs"] == [TLP_MARKINGS["red"]]
    relationship = next(item for item in bundle["objects"] if item["type"] == "relationship")
    assert relationship["object_marking_refs"] == [TLP_MARKINGS["amber"]]
    second = build_stix_bundle(db, [clear, green, amber, red])
    assert {item["id"] for item in bundle["objects"]} == {item["id"] for item in second["objects"]}
    assert exported[f"DOMAIN {green.value}"]["id"] == f"indicator--{green.id}"
    assert relationship["id"] == f"relationship--{edge.id}"


def test_stix_pattern_escapes_backslash_and_quote():
    item = Indicator(value="https://example.com/a\\b'c", type="url")
    assert _pattern(item) == "[url:value = 'https://example.com/a\\\\b\\'c']"


def test_stix_validity_window_handles_reversed_source_dates(db):
    now = utcnow()
    item = new_indicator(db, "reversed.example", "domain", "amber")
    item.first_seen = now
    item.last_seen = now - timedelta(days=2)
    db.commit()
    exported = build_stix_bundle(db, [item])["objects"][0]
    assert exported["valid_from"] < exported["valid_until"]

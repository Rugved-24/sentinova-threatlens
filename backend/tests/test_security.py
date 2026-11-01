from __future__ import annotations

import pytest
from app.security import (
    can_view_tlp,
    create_access_token,
    decode_access_token,
    decrypt_json,
    decrypt_secret,
    encrypt_json,
    encrypt_secret,
    hash_password,
    password_policy_errors,
    validate_outbound_url,
    verify_password,
)
from fastapi import HTTPException


def test_password_hash_roundtrip():
    hashed = hash_password("Correct-Horse-Battery-9!")
    assert hashed != "Correct-Horse-Battery-9!"
    assert verify_password(hashed, "Correct-Horse-Battery-9!")
    assert not verify_password(hashed, "wrong-password")


@pytest.mark.parametrize(
    ("password", "valid"),
    [
        ("short", False),
        ("alllowercase123!", False),
        ("ALLUPPERCASE123!", False),
        ("NoNumbersHere!", False),
        ("NoSymbolsHere123", False),
        ("Valid-Password-2026!", True),
    ],
)
def test_password_policy(password, valid):
    assert (not password_policy_errors(password)) is valid


def test_aes_roundtrip():
    ciphertext = encrypt_secret("sensitive value")
    assert ciphertext != "sensitive value"
    assert decrypt_secret(ciphertext) == "sensitive value"
    payload = {"X-API-Key": "abc123", "nested": {"value": 1}}
    assert decrypt_json(encrypt_json(payload)) == payload


def test_jwt_roundtrip_and_tamper():
    token, expires = create_access_token("user-1", "analyst")
    payload = decode_access_token(token)
    assert payload["sub"] == "user-1"
    assert payload["role"] == "analyst"
    assert expires > 0
    with pytest.raises(HTTPException):
        decode_access_token(token + "x")


@pytest.mark.parametrize(
    ("url", "valid"),
    [
        ("https://example.com/feed.txt", True),
        ("http://1.1.1.1/feed", True),
        ("http://127.0.0.1/feed", False),
        ("http://10.0.0.5/feed", False),
        ("http://192.0.2.1/feed", False),
        ("http://169.254.169.254/latest/meta-data", False),
        ("file:///etc/passwd", False),
        ("ftp://example.com/feed", False),
        ("http://[::1]/feed", False),
        ("", False),
    ],
)
def test_ssrf_validation(url, valid):
    if valid:
        assert validate_outbound_url(url) == url
    else:
        with pytest.raises(ValueError):
            validate_outbound_url(url)


def test_tlp_clearance():
    assert can_view_tlp("admin", "red")
    assert can_view_tlp("analyst", "amber")
    assert not can_view_tlp("analyst", "red")
    assert not can_view_tlp("executive", "clear")

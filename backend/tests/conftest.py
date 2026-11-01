from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

TMP = Path(tempfile.mkdtemp(prefix="threatlens-tests-"))
os.environ["THREATLENS_TESTING"] = "1"
os.environ["THREATLENS_SKIP_SEED"] = "1"
os.environ["DB_FILE"] = str(TMP / "test.db")
os.environ["REPORTS_DIR"] = str(TMP / "reports")
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-hs256-signing-2026"
os.environ["DEMO_MODE"] = "true"
os.environ["WEBHOOK_SECRET"] = "test-webhook-secret-that-is-long-enough-2026"

from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed_database  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PASSWORD = "ThreatLens#2026!"
ACCOUNTS = {
    "admin": "admin@threatlens.io",
    "engineer": "engineer@threatlens.io",
    "responder": "responder@threatlens.io",
    "hunter": "hunter@threatlens.io",
    "analyst": "analyst@threatlens.io",
    "executive": "exec@threatlens.io",
}


@pytest.fixture(scope="session", autouse=True)
def seeded():
    seed_database()


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def tokens(client):
    result = {}
    for role, email in ACCOUNTS.items():
        response = client.post(
            "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
        )
        assert response.status_code == 200, response.text
        result[role] = response.json()["access_token"]
    return result


@pytest.fixture
def headers(tokens):
    def make(role: str = "admin") -> dict[str, str]:
        return {"Authorization": f"Bearer {tokens[role]}"}

    return make


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

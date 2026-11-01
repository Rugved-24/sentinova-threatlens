from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
FRONTEND_DIST = ROOT / "frontend" / "dist"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    app_name: str = "ThreatLens"
    app_env: str = "development"
    demo_mode: bool = True
    secret_key: str = ""
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    cookie_secure: bool = False
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    login_rate_limit: int = 10
    rate_limit_per_minute: int = 240
    max_request_bytes: int = 5 * 1024 * 1024
    feed_timeout_seconds: int = 20
    require_mfa_for_admin: bool = False
    admin_email: str = ""
    admin_password: str = ""
    db_file: str = ""
    reports_dir: str = ""
    database_url: str = ""
    redis_url: str = ""
    elasticsearch_url: str = ""
    elasticsearch_index_prefix: str = "threatlens"
    celery_broker_url: str = ""
    celery_result_backend: str = ""
    run_scheduler: bool = True
    retention_days: int = 365
    notification_retention_days: int = 90

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    threatfox_api_key: str = ""
    greynoise_api_key: str = ""

    webhook_secret: str = ""
    outbound_webhook_url: str = ""
    outbound_webhook_secret: str = ""

    @property
    def is_dev(self) -> bool:
        return self.app_env.lower() in {"dev", "development", "local"}

    @property
    def cors_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def db_path(self) -> Path:
        return Path(self.db_file) if self.db_file else DATA_DIR / "threatlens.db"

    @property
    def sqlalchemy_url(self) -> str:
        """Return the configured database URL, falling back to local SQLite."""
        raw = (self.database_url or "").strip()
        if not raw:
            return ""
        if raw.startswith("postgres://"):
            raw = raw.replace("postgres://", "postgresql+psycopg://", 1)
        elif raw.startswith("postgresql://"):
            raw = raw.replace("postgresql://", "postgresql+psycopg://", 1)
        return raw

    @property
    def event_bus_enabled(self) -> bool:
        return bool(self.redis_url.strip())

    @property
    def search_backend(self) -> str:
        if self.elasticsearch_url.strip():
            return "elasticsearch"
        return "database"

    @property
    def report_dir(self) -> Path:
        path = Path(self.reports_dir) if self.reports_dir else DATA_DIR / "reports"
        path.mkdir(parents=True, exist_ok=True)
        return path


def _load_or_create_secret() -> str:
    """Use SECRET_KEY when supplied, otherwise create a private local key once."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / ".dev_secret"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    value = secrets.token_urlsafe(48)
    path.write_text(value, encoding="utf-8")
    return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    strict_production = settings.app_env.lower() == "production" and not settings.demo_mode
    if strict_production and (not settings.secret_key or len(settings.secret_key) < 32):
        raise RuntimeError("Production requires SECRET_KEY with at least 32 characters")
    if strict_production and (not settings.admin_email or not settings.admin_password):
        raise RuntimeError("Production requires ADMIN_EMAIL and ADMIN_PASSWORD")
    if not settings.secret_key or len(settings.secret_key) < 32:
        settings.secret_key = _load_or_create_secret()
    if settings.app_env.lower() == "production" and not settings.cookie_secure:
        settings.cookie_secure = True
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return settings

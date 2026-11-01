from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings
from .models import Base

_settings = get_settings()
_db_override = os.getenv("THREATLENS_DB", "").strip()
_configured_url = _db_override or _settings.sqlalchemy_url

if _configured_url == ":memory:":
    _database_url = "sqlite+pysqlite:///:memory:"
    engine = create_engine(
        _database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
elif _configured_url.startswith(("sqlite:", "postgresql", "postgres:")):
    _database_url = _configured_url
    engine = create_engine(_database_url, pool_pre_ping=True, pool_recycle=1800)
else:
    _sqlite_path = Path(_configured_url or _settings.db_path)
    _sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    _database_url = f"sqlite+pysqlite:///{_sqlite_path.as_posix()}"
    engine = create_engine(
        _database_url,
        connect_args={"check_same_thread": False, "timeout": 30},
        pool_pre_ping=True,
    )

IS_SQLITE = engine.dialect.name == "sqlite"
IS_POSTGRES = engine.dialect.name == "postgresql"

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


if IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.execute("PRAGMA cache_size=-32000")
        cursor.close()


FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS indicator_fts USING fts5(
    indicator_id UNINDEXED,
    value,
    notes,
    tags,
    attack,
    tokenize = 'unicode61'
)
"""

IMMUTABLE_SCHEMA = [
    """
    CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
    BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
    BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_timeline_no_update
    BEFORE UPDATE ON incident_timeline
    BEGIN SELECT RAISE(ABORT, 'incident_timeline is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_timeline_no_delete
    BEFORE DELETE ON incident_timeline
    BEGIN SELECT RAISE(ABORT, 'incident_timeline is append-only'); END
    """,
]

POSTGRES_IMMUTABLE_SCHEMA = [
    """
    CREATE OR REPLACE FUNCTION threatlens_prevent_mutation() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS trg_audit_no_update ON audit_log",
    """
    CREATE TRIGGER trg_audit_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION threatlens_prevent_mutation()
    """,
    "DROP TRIGGER IF EXISTS trg_audit_no_delete ON audit_log",
    """
    CREATE TRIGGER trg_audit_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION threatlens_prevent_mutation()
    """,
    "DROP TRIGGER IF EXISTS trg_timeline_no_update ON incident_timeline",
    """
    CREATE TRIGGER trg_timeline_no_update BEFORE UPDATE ON incident_timeline
    FOR EACH ROW EXECUTE FUNCTION threatlens_prevent_mutation()
    """,
    "DROP TRIGGER IF EXISTS trg_timeline_no_delete ON incident_timeline",
    """
    CREATE TRIGGER trg_timeline_no_delete BEFORE DELETE ON incident_timeline
    FOR EACH ROW EXECUTE FUNCTION threatlens_prevent_mutation()
    """,
]

MIGRATION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def _run_migrations(connection) -> None:
    connection.execute(text(MIGRATION_TABLE))
    applied = set(connection.execute(text("SELECT version FROM schema_migrations")).scalars())
    version = "20261029_01_alert_rule_categories_and_users"
    if version in applied:
        return
    columns = {column["name"] for column in inspect(connection).get_columns("alert_rules")}
    if "categories" not in columns:
        definition = "JSON NOT NULL DEFAULT '[]'" if IS_SQLITE else "JSON NOT NULL DEFAULT '[]'::json"
        connection.execute(text(f"ALTER TABLE alert_rules ADD COLUMN categories {definition}"))
    if "route_user_ids" not in columns:
        definition = "JSON NOT NULL DEFAULT '[]'" if IS_SQLITE else "JSON NOT NULL DEFAULT '[]'::json"
        connection.execute(text(f"ALTER TABLE alert_rules ADD COLUMN route_user_ids {definition}"))
    connection.execute(
        text("INSERT INTO schema_migrations (version) VALUES (:version)"),
        {"version": version},
    )


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        _run_migrations(connection)
        if IS_SQLITE:
            connection.execute(text(FTS_SCHEMA))
            for statement in IMMUTABLE_SCHEMA:
                connection.execute(text(statement))
        elif IS_POSTGRES:
            for statement in POSTGRES_IMMUTABLE_SCHEMA:
                connection.execute(text(statement))


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def rebuild_fts(db: Session) -> None:
    if not IS_SQLITE:
        return
    db.execute(text("DELETE FROM indicator_fts"))
    db.execute(
        text(
            """
            INSERT INTO indicator_fts (indicator_id, value, notes, attack)
            SELECT i.id, i.value, COALESCE(i.notes, ''),
                   COALESCE((SELECT group_concat(technique_id, ' ')
                             FROM indicator_attack ia WHERE ia.indicator_id = i.id), '')
            FROM indicators i
            """
        )
    )
    db.commit()


def refresh_fts_row(db: Session, indicator_id: str) -> None:
    if IS_SQLITE:
        db.execute(text("DELETE FROM indicator_fts WHERE indicator_id = :id"), {"id": indicator_id})
        db.execute(
            text(
                """
                INSERT INTO indicator_fts (indicator_id, value, notes, tags, attack)
                SELECT i.id, i.value, COALESCE(i.notes, ''),
                       COALESCE((SELECT group_concat(t.name, ' ') FROM indicator_tags it
                                 JOIN tags t ON t.id = it.tag_id WHERE it.indicator_id = i.id), ''),
                       COALESCE((SELECT group_concat(ia.technique_id, ' ') FROM indicator_attack ia
                                 WHERE ia.indicator_id = i.id), '')
                FROM indicators i WHERE i.id = :id
                """
            ),
            {"id": indicator_id},
        )
        return
    if _settings.search_backend == "elasticsearch" and os.getenv("THREATLENS_TESTING") != "1":
        try:
            from .indexing import index_indicator_by_id

            index_indicator_by_id(db, indicator_id)
        except Exception:
            import logging

            logging.getLogger("threatlens.db").exception(
                "Elasticsearch indexing failed; SQL search fallback remains active"
            )

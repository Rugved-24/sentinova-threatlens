from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .utils import new_id, utcnow


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(32), index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    preferences: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Feed(Base):
    __tablename__ = "feeds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_header_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    schedule_minutes: Mapped[int] = mapped_column(Integer, default=60)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("value", "type", name="uq_indicator_value_type"),
        Index("ix_indicator_active_sev", "status", "severity_score"),
        Index("ix_indicator_type_sev", "type", "severity_score"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    value: Mapped[str] = mapped_column(Text, index=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    severity_score: Mapped[int] = mapped_column(SmallInteger, default=0, index=True)
    confidence: Mapped[int] = mapped_column(SmallInteger, default=0)
    tlp: Mapped[str] = mapped_column(String(8), default="amber")
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    geo: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    asn: Mapped[str | None] = mapped_column(String(160), nullable=True)
    internal_sightings: Mapped[int] = mapped_column(Integer, default=0)
    malicious_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_count: Mapped[int] = mapped_column(Integer, default=1)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)


class IndicatorSource(Base):
    __tablename__ = "indicator_sources"
    __table_args__ = (UniqueConstraint("indicator_id", "source_name", name="uq_ind_source"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    indicator_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    feed_id: Mapped[str | None] = mapped_column(ForeignKey("feeds.id"), nullable=True)
    source_name: Mapped[str] = mapped_column(String(120))
    source_confidence: Mapped[int] = mapped_column(SmallInteger, default=50)
    source_reliability: Mapped[float] = mapped_column(Float, default=0.8)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    raw_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Enrichment(Base):
    __tablename__ = "enrichments"
    __table_args__ = (Index("ix_enrich_ind_provider", "indicator_id", "provider", "kind"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    indicator_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    score: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    color: Mapped[str] = mapped_column(String(16), default="#38bdf8")


class IndicatorTag(Base):
    __tablename__ = "indicator_tags"

    indicator_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[str] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)


class IndicatorRelationship(Base):
    __tablename__ = "indicator_relationships"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "relation_type", name="uq_relationship"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    relation_type: Mapped[str] = mapped_column(String(32), default="related-to")
    confidence: Mapped[int] = mapped_column(SmallInteger, default=50)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    tactic: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(Text, default="")
    platforms: Mapped[list[str]] = mapped_column(JSON, default=list)


class IndicatorAttack(Base):
    __tablename__ = "indicator_attack"

    indicator_id: Mapped[str] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(
        ForeignKey("attack_techniques.id", ondelete="CASCADE"), primary_key=True
    )


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_score: Mapped[int] = mapped_column(SmallInteger, default=70)
    types: Mapped[list[str]] = mapped_column(JSON, default=list)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    tlp_max: Mapped[str] = mapped_column(String(8), default="red")
    route_roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    route_user_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_status_sev", "status", "score"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[int] = mapped_column(SmallInteger, default=0)
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    rule_id: Mapped[str | None] = mapped_column(ForeignKey("alert_rules.id"), nullable=True)
    indicator_id: Mapped[str | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True, index=True
    )
    assignee_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    tlp: Mapped[str] = mapped_column(String(8), default="amber")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(240))
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="high")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    checklist: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    indicator_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(48))
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    user_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    host: Mapped[str | None] = mapped_column(String(120), nullable=True)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(240))
    kind: Mapped[str] = mapped_column(String(32), default="executive")
    requested_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)


class SavedHunt(Base):
    __tablename__ = "saved_hunts"
    __table_args__ = (UniqueConstraint("name", "created_by", name="uq_hunt_name_owner"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120))
    query: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(240))
    body: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(32), default="alert")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    link: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), index=True)


class AuditChainLock(Base):
    __tablename__ = "audit_chain_lock"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)


class WebhookReceipt(Base):
    __tablename__ = "webhook_receipts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

Role = Literal["admin", "engineer", "responder", "hunter", "analyst", "executive"]
Tlp = Literal["clear", "green", "amber", "red"]
IndicatorType = Literal[
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve"
]
IndicatorStatus = Literal["active", "expired", "whitelisted", "under_review"]
AlertStatus = Literal["new", "acknowledged", "in-progress", "resolved", "closed"]
IncidentStatus = Literal["open", "investigating", "contained", "closed"]


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    otp: str | None = Field(default=None, pattern=r"^\d{6}$")


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    preferences: dict[str, Any] = {}
    last_login_at: str | None = None


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class UserCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=2, max_length=120)
    role: Role
    password: str = Field(min_length=12, max_length=256)


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class ProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    preferences: dict[str, Any] | None = None


class ChangePassword(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MfaEnable(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class MfaDisable(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(pattern=r"^\d{6}$")


class IndicatorCreate(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    type: IndicatorType | None = None
    tlp: Tlp = "amber"
    tags: list[str] = Field(default_factory=list, max_length=20)
    attack_ids: list[str] = Field(default_factory=list, max_length=20)
    notes: str | None = Field(default=None, max_length=4000)
    confidence: int = Field(default=60, ge=0, le=100)


class IndicatorUpdate(BaseModel):
    notes: str | None = Field(default=None, max_length=4000)
    tlp: Tlp | None = None
    status: IndicatorStatus | None = None
    add_tags: list[str] = Field(default_factory=list, max_length=20)
    remove_tags: list[str] = Field(default_factory=list, max_length=20)
    attack_ids: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("notes")
    @classmethod
    def clean_notes(cls, value: str | None) -> str | None:
        return value.strip()[:4000] if value is not None else None


class RelationshipCreate(BaseModel):
    target_value: str = Field(min_length=1, max_length=2048)
    target_type: IndicatorType | None = None
    relation_type: str = Field(default="related-to", min_length=2, max_length=32)


class AlertPatch(BaseModel):
    status: AlertStatus | None = None
    assignee_id: str | None = None
    incident_id: str | None = None


class AlertRuleIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    enabled: bool = True
    min_score: int = Field(default=70, ge=0, le=100)
    types: list[IndicatorType] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list, max_length=20)
    categories: list[str] = Field(default_factory=list, max_length=20)
    tlp_max: Tlp = "red"
    route_roles: list[Role] = Field(default_factory=list, max_length=10)
    route_user_ids: list[str] = Field(default_factory=list, max_length=50)


class AlertRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    enabled: bool | None = None
    min_score: int | None = Field(default=None, ge=0, le=100)
    types: list[IndicatorType] | None = Field(default=None)
    sources: list[str] | None = Field(default=None, max_length=20)
    categories: list[str] | None = Field(default=None, max_length=20)
    tlp_max: Tlp | None = None
    route_roles: list[Role] | None = Field(default=None, max_length=10)
    route_user_ids: list[str] | None = Field(default=None, max_length=50)


class EscalateIn(BaseModel):
    title: str | None = Field(default=None, max_length=240)
    summary: str | None = Field(default=None, max_length=2000)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=240)
    summary: str = Field(default="", max_length=4000)
    severity: Literal["critical", "high", "medium", "low"] = "high"
    status: IncidentStatus = "open"
    owner_id: str | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=240)
    summary: str | None = Field(default=None, max_length=4000)
    status: IncidentStatus | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None
    owner_id: str | None = None
    checklist: list[dict[str, Any]] | None = None


class TimelineCreate(BaseModel):
    event_type: str = Field(default="note", min_length=2, max_length=32)
    message: str = Field(min_length=1, max_length=4000)
    indicator_id: str | None = None


class FeedCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: Literal[
        "demo", "kev", "urlhaus", "openphish", "feodo", "blocklistde",
        "et_compromised", "cins", "phishing_army", "otx", "abuseipdb",
        "threatfox", "taxii",
    ]
    url: str | None = Field(default=None, max_length=2048)
    auth_key: str | None = Field(default=None, max_length=512)
    enabled: bool = True
    schedule_minutes: int = Field(default=60, ge=5, le=1440)
    config: dict[str, Any] = Field(default_factory=dict)


class FeedUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    url: str | None = Field(default=None, max_length=2048)
    auth_key: str | None = Field(default=None, max_length=512)
    enabled: bool | None = None
    schedule_minutes: int | None = Field(default=None, ge=5, le=1440)
    config: dict[str, Any] | None = None


class HuntCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    query: dict[str, Any] = Field(default_factory=dict)


class ReportCreate(BaseModel):
    title: str = Field(default="ThreatLens Intelligence Report", max_length=240)
    kind: Literal["executive", "operational", "incident"] = "executive"
    incident_id: str | None = None


class NotificationRead(BaseModel):
    ids: list[str] = Field(default_factory=list, max_length=200)
    all: bool = False


class HookPayload(BaseModel):
    indicators: list[dict[str, Any]] = Field(default_factory=list, max_length=200)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=200)

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record_audit
from ..config import get_settings
from ..correlation import correlate_indicator, create_alerts_for_indicator
from ..db import get_db
from ..deps import require
from ..feeds import FEED_DEFAULTS, RELIABILITY, parse_csv_records, run_feed
from ..ingest import upsert_indicator
from ..models import Feed, User
from ..schemas import FeedCreate, FeedUpdate, Tlp
from ..security import encrypt_json, validate_outbound_url
from ..serializers import feed_items

router = APIRouter(tags=["feeds"])
settings = get_settings()

AUTH_HEADERS = {
    "otx": "X-OTX-API-KEY",
    "abuseipdb": "Key",
    "threatfox": "Auth-Key",
    "urlhaus": "Auth-Key",
}
AUTH_REQUIRED = {"otx", "abuseipdb", "threatfox"}


def _auth_header(kind: str, key: str | None) -> str | None:
    if not key:
        return None
    if kind in AUTH_HEADERS:
        return encrypt_json({AUTH_HEADERS[kind]: key})
    if kind == "taxii":
        return encrypt_json({"Authorization": f"Bearer {key}"})
    return encrypt_json({"Authorization": key})


def _resolve_url(kind: str, url: str | None) -> str | None:
    resolved = url or FEED_DEFAULTS.get(kind)
    if kind == "demo":
        return None
    if not resolved:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "url_required", "message": "A feed URL is required"},
        )
    try:
        validate_outbound_url(resolved)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_feed_url", "message": str(exc)},
        ) from exc
    return resolved


@router.get("/feeds")
def list_feeds(
    user: User = Depends(require("configure_feeds")),
    db: Session = Depends(get_db),
):
    feeds = db.execute(select(Feed).order_by(Feed.created_at.asc())).scalars().all()
    return {"data": feed_items(db, feeds)}


@router.post("/feeds", status_code=201)
def create_feed(
    payload: FeedCreate,
    request: Request,
    user: User = Depends(require("configure_feeds")),
    db: Session = Depends(get_db),
):
    if db.execute(select(Feed).where(Feed.name == payload.name.strip())).scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail={"error_code": "duplicate_feed", "message": "Feed name already exists"},
        )
    if payload.kind in AUTH_REQUIRED and not payload.auth_key and payload.enabled:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "auth_required",
                "message": f"{payload.kind} requires an API key before it can be enabled",
            },
        )
    url = _resolve_url(payload.kind, payload.url)
    feed = Feed(
        name=payload.name.strip(),
        kind=payload.kind,
        url=url,
        auth_header_enc=_auth_header(payload.kind, payload.auth_key),
        enabled=payload.enabled,
        schedule_minutes=payload.schedule_minutes,
        config=payload.config,
    )
    db.add(feed)
    db.flush()
    record_audit(
        db,
        "feed.create",
        actor=user,
        object_type="feed",
        object_id=feed.id,
        detail={"name": feed.name, "kind": feed.kind, "enabled": feed.enabled},
        request=request,
    )
    db.commit()
    return {"data": feed_items(db, [feed])[0]}


@router.patch("/feeds/{feed_id}")
def update_feed(
    feed_id: str,
    payload: FeedUpdate,
    request: Request,
    user: User = Depends(require("configure_feeds")),
    db: Session = Depends(get_db),
):
    feed = db.get(Feed, feed_id)
    if feed is None:
        raise HTTPException(status_code=404, detail={"error_code": "not_found", "message": "Feed not found"})
    changes = {}
    if payload.name is not None:
        feed.name = payload.name.strip()
        changes["name"] = feed.name
    if payload.url is not None:
        feed.url = _resolve_url(feed.kind, payload.url)
        changes["url"] = feed.url
    if payload.auth_key is not None:
        feed.auth_header_enc = _auth_header(feed.kind, payload.auth_key)
        changes["auth"] = "updated" if payload.auth_key else "cleared"
    if payload.schedule_minutes is not None:
        feed.schedule_minutes = payload.schedule_minutes
        changes["schedule_minutes"] = feed.schedule_minutes
    if payload.config is not None:
        feed.config = payload.config
        changes["config"] = "updated"
    if payload.enabled is not None:
        if (
            payload.enabled
            and feed.kind in AUTH_REQUIRED
            and not feed.auth_header_enc
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "auth_required",
                    "message": f"{feed.kind} requires an API key before it can be enabled",
                },
            )
        feed.enabled = payload.enabled
        changes["enabled"] = payload.enabled
    record_audit(
        db,
        "feed.update",
        actor=user,
        object_type="feed",
        object_id=feed.id,
        detail={"changes": changes},
        request=request,
    )
    db.commit()
    return {"data": feed_items(db, [feed])[0]}


@router.post("/feeds/{feed_id}/run", status_code=202)
def run_feed_now(
    feed_id: str,
    background: BackgroundTasks,
    request: Request,
    user: User = Depends(require("configure_feeds")),
    db: Session = Depends(get_db),
):
    feed = db.get(Feed, feed_id)
    if feed is None:
        raise HTTPException(status_code=404, detail={"error_code": "not_found", "message": "Feed not found"})
    record_audit(
        db,
        "feed.trigger",
        actor=user,
        object_type="feed",
        object_id=feed.id,
        detail={"name": feed.name},
        request=request,
    )
    db.commit()
    background.add_task(run_feed, feed.id)
    return {"data": {"status": "queued", "feed_id": feed.id}}


@router.post("/feeds/import/csv")
async def import_csv(
    request: Request,
    file: UploadFile = File(...),
    source: str = Form(default="CSV Import", min_length=2, max_length=120),
    tlp: Tlp = Form(default="amber"),
    user: User = Depends(require("configure_feeds")),
    db: Session = Depends(get_db),
):
    raw = await file.read(settings.max_request_bytes + 1)
    if len(raw) > settings.max_request_bytes:
        raise HTTPException(
            status_code=413,
            detail={"error_code": "payload_too_large", "message": "CSV exceeds the upload limit"},
        )
    try:
        records = parse_csv_records(raw.decode("utf-8-sig"), source=source.strip(), default_tlp=tlp)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_csv", "message": str(exc)},
        ) from exc

    created = updated = rejected = alerts = 0
    for record in records:
        indicator, was_created = upsert_indicator(
            db,
            value=record["value"],
            kind=record.get("type"),
            source=record.get("source") or source.strip(),
            confidence=record.get("confidence", 60),
            reliability=record.get("reliability", 0.7),
            tlp=record.get("tlp", tlp),
            tags=record.get("tags"),
            attack_ids=record.get("attack_ids"),
            notes=record.get("notes"),
            raw_ref=record.get("raw_ref"),
            first_seen=record.get("first_seen"),
            last_seen=record.get("last_seen"),
        )
        if indicator is None:
            rejected += 1
            continue
        created += int(was_created)
        updated += int(not was_created)
        events = correlate_indicator(db, indicator)
        alerts += len(create_alerts_for_indicator(db, indicator, events))
    record_audit(
        db,
        "feed.csv_import",
        actor=user,
        object_type="feed_import",
        detail={
            "filename": (file.filename or "upload.csv")[:180],
            "source": source.strip(),
            "rows": len(records),
            "created": created,
            "updated": updated,
            "rejected": rejected,
            "alerts": alerts,
        },
        request=request,
    )
    db.commit()
    return {
        "data": {
            "rows": len(records),
            "created": created,
            "updated": updated,
            "rejected": rejected,
            "alerts": alerts,
        }
    }


@router.get("/feeds/meta")
def feed_metadata(
    user: User = Depends(require("configure_feeds")),
):
    return {
        "data": {
            "kinds": [
                {"kind": kind, "reliability": reliability, "default_url": FEED_DEFAULTS.get(kind)}
                for kind, reliability in RELIABILITY.items()
            ],
            "auth_required": sorted(AUTH_REQUIRED),
        }
    }

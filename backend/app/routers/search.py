from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import record_audit
from ..db import get_db
from ..deps import require
from ..models import SavedHunt, User
from ..schemas import HuntCreate
from ..search_service import search_events, search_indicators
from ..serializers import indicator_list_items
from ..utils import iso

router = APIRouter(tags=["search"])


@router.get("/search")
def search(
    user: User = Depends(require("search")),
    db: Session = Depends(get_db),
    q: str = "",
    type: Annotated[list[str] | None, Query()] = None,
    severity_min: int | None = None,
    severity_max: int | None = None,
    tlp: Annotated[list[str] | None, Query()] = None,
    status: str | None = None,
    source: str | None = None,
    tag: str | None = None,
    attack: str | None = None,
    country: str | None = None,
    kev: bool | None = None,
    sort: str = "severity_desc",
    page: int = 1,
    size: int = 25,
):
    result = search_indicators(
        db,
        role=user.role,
        q=q,
        types=type,
        severity_min=severity_min,
        severity_max=severity_max,
        tlp=tlp,
        status=status,
        source=source,
        tag=tag,
        attack=attack,
        country=country,
        kev=kev,
        sort=sort,
        page=page,
        size=size,
    )
    return {
        "data": indicator_list_items(db, result["items"]),
        "meta": {
            "total": result["total"],
            "page": result["page"],
            "size": result["size"],
            "facets": result["facets"],
        },
    }


@router.get("/events")
def list_events(
    user: User = Depends(require("search")),
    db: Session = Depends(get_db),
    q: str = "",
    event_type: str | None = None,
    page: int = 1,
    size: int = 25,
):
    return {"data": search_events(db, q=q, event_type=event_type, page=page, size=size)}


@router.get("/hunts")
def list_hunts(
    user: User = Depends(require("create_hunts")),
    db: Session = Depends(get_db),
):
    hunts = db.execute(
        select(SavedHunt).where(SavedHunt.created_by == user.id).order_by(SavedHunt.created_at.desc())
    ).scalars().all()
    return {
        "data": [
            {"id": hunt.id, "name": hunt.name, "query": hunt.query, "created_at": iso(hunt.created_at)}
            for hunt in hunts
        ]
    }


@router.post("/hunts", status_code=201)
def create_hunt(
    payload: HuntCreate,
    request: Request,
    user: User = Depends(require("create_hunts")),
    db: Session = Depends(get_db),
):
    hunt = SavedHunt(name=payload.name.strip(), query=payload.query, created_by=user.id)
    db.add(hunt)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={"error_code": "duplicate_hunt", "message": "A hunt with this name already exists"},
        ) from exc
    record_audit(
        db,
        "hunt.create",
        actor=user,
        object_type="hunt",
        object_id=hunt.id,
        detail={"name": hunt.name, "query": hunt.query},
        request=request,
    )
    db.commit()
    return {"data": {"id": hunt.id, "name": hunt.name, "query": hunt.query, "created_at": iso(hunt.created_at)}}


@router.delete("/hunts/{hunt_id}", status_code=204)
def delete_hunt(
    hunt_id: str,
    request: Request,
    user: User = Depends(require("create_hunts")),
    db: Session = Depends(get_db),
):
    hunt = db.get(SavedHunt, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail={"error_code": "not_found", "message": "Hunt not found"})
    if hunt.created_by != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail={"error_code": "forbidden", "message": "Not your hunt"})
    record_audit(
        db,
        "hunt.delete",
        actor=user,
        object_type="hunt",
        object_id=hunt.id,
        detail={"name": hunt.name},
        request=request,
    )
    db.delete(hunt)
    db.commit()
    return None

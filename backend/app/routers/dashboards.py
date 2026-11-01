from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..analytics import analyst_overview, attack_matrix, executive_overview, geo_overview
from ..db import get_db
from ..deps import require
from ..models import AttackTechnique, User

router = APIRouter(tags=["dashboards"])


@router.get("/dashboards/executive")
def executive_dashboard(
    user: User = Depends(require("view_dashboards")),
    db: Session = Depends(get_db),
):
    return {"data": executive_overview(db, user.role)}


@router.get("/dashboards/analyst")
def analyst_dashboard(
    user: User = Depends(require("manage_alerts")),
    db: Session = Depends(get_db),
):
    return {"data": analyst_overview(db, user)}


@router.get("/dashboards/geo")
def geo_dashboard(
    user: User = Depends(require("view_dashboards")),
    db: Session = Depends(get_db),
):
    return {"data": geo_overview(db, user.role)}


@router.get("/attack/matrix")
def attack_overlay(
    user: User = Depends(require("view_dashboards")),
    db: Session = Depends(get_db),
):
    return {"data": attack_matrix(db, user.role)}


@router.get("/attack/techniques")
def list_techniques(
    ids: Annotated[list[str] | None, Query()] = None,
    q: str = "",
    user: User = Depends(require("view_dashboards")),
    db: Session = Depends(get_db),
):
    query = select(AttackTechnique)
    if ids:
        query = query.where(AttackTechnique.id.in_([value.upper() for value in ids[:100]]))
    if q:
        query = query.where(
            AttackTechnique.name.ilike(f"%{q[:80]}%") | AttackTechnique.id.ilike(f"%{q[:20]}%")
        )
    techniques = db.execute(query.order_by(AttackTechnique.id.asc()).limit(100)).scalars().all()
    return {
        "data": [
            {
                "id": technique.id,
                "name": technique.name,
                "tactic": technique.tactic,
                "description": technique.description,
                "url": technique.url,
                "platforms": technique.platforms,
            }
            for technique in techniques
        ]
    }

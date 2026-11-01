from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..audit import record_audit
from ..correlation import correlate_indicator, create_alerts_for_indicator
from ..db import get_db
from ..deps import require
from ..enrichment import enrich_indicator
from ..events import manager
from ..ingest import add_relationship, attach_attack, attach_tag, recompute_indicator, upsert_indicator
from ..models import (
    Indicator,
    IndicatorAttack,
    IndicatorRelationship,
    IndicatorTag,
    Tag,
    User,
)
from ..normalize import canonicalize
from ..reporting import build_stix_bundle, export_csv
from ..schemas import IndicatorCreate, IndicatorUpdate, RelationshipCreate
from ..search_service import search_indicators
from ..security import can_view_tlp
from ..serializers import indicator_detail, indicator_list_items
from ..utils import utcnow

router = APIRouter(tags=["indicators"])


def _get_indicator(db: Session, indicator_id: str, user: User) -> Indicator:
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "not_found", "message": "Indicator not found"},
        )
    if not can_view_tlp(user.role, indicator.tlp):
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "tlp_restricted",
                "message": "Indicator handling caveat exceeds your clearance",
            },
        )
    return indicator


def _notify_indicator(indicator: Indicator) -> None:
    if indicator.severity_score >= 60 and indicator.status == "active":
        manager.publish(
            "indicators.high_severity",
            {
                "id": indicator.id,
                "value": indicator.value,
                "type": indicator.type,
                "score": indicator.severity_score,
                "tlp": indicator.tlp,
            },
        )


@router.get("/indicators")
def list_indicators(
    user: User = Depends(require("view_indicators")),
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


@router.post("/indicators", status_code=201)
def create_indicator(
    payload: IndicatorCreate,
    request: Request,
    user: User = Depends(require("edit_indicators")),
    db: Session = Depends(get_db),
):
    normalized = canonicalize(payload.value, payload.type)
    if normalized is None:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_indicator", "message": "Unrecognised indicator value"},
        )
    value, kind = normalized
    if not can_view_tlp(user.role, payload.tlp):
        raise HTTPException(
            status_code=403,
            detail={"error_code": "tlp_restricted", "message": "Cannot create above your TLP clearance"},
        )
    indicator, created = upsert_indicator(
        db,
        value=value,
        kind=kind,
        source=f"Analyst submission · {user.name}",
        confidence=payload.confidence,
        reliability=0.6,
        tlp=payload.tlp,
        tags=payload.tags,
        attack_ids=payload.attack_ids,
        notes=payload.notes,
        malicious_ratio=0.3,
        authorize=lambda existing: _get_indicator(db, existing.id, user),
    )
    events = correlate_indicator(db, indicator) if indicator else []
    alerts = create_alerts_for_indicator(db, indicator, events) if indicator else []
    record_audit(
        db,
        "indicator.create" if created else "indicator.submit_duplicate",
        actor=user,
        object_type="indicator",
        object_id=indicator.id if indicator else None,
        detail={"value": value, "type": kind, "created": created},
        request=request,
    )
    db.commit()
    if indicator:
        _notify_indicator(indicator)
    return {
        "data": indicator_detail(db, indicator, role=user.role),
        "meta": {"created": created, "alerts": len(alerts)},
    }


@router.get("/indicators/{indicator_id}")
def get_indicator(
    indicator_id: str,
    user: User = Depends(require("view_indicators")),
    db: Session = Depends(get_db),
):
    return {"data": indicator_detail(db, _get_indicator(db, indicator_id, user), role=user.role)}


@router.patch("/indicators/{indicator_id}")
def update_indicator(
    indicator_id: str,
    payload: IndicatorUpdate,
    request: Request,
    user: User = Depends(require("edit_indicators")),
    db: Session = Depends(get_db),
):
    indicator = _get_indicator(db, indicator_id, user)
    changes = {}
    if payload.notes is not None:
        indicator.notes = payload.notes
        changes["notes"] = "updated"
    if payload.tlp is not None:
        if not can_view_tlp(user.role, payload.tlp):
            raise HTTPException(
                status_code=403,
                detail={"error_code": "tlp_restricted", "message": "Cannot raise TLP above clearance"},
            )
        indicator.tlp = payload.tlp
        changes["tlp"] = payload.tlp
    if payload.status is not None:
        indicator.status = payload.status
        changes["status"] = payload.status
    add_tags = list(dict.fromkeys(" ".join(tag.lower().split())[:64] for tag in payload.add_tags))
    remove_tags = list(dict.fromkeys(" ".join(tag.lower().split())[:64] for tag in payload.remove_tags))
    for tag_name in add_tags:
        attach_tag(db, indicator.id, tag_name)
    db.flush()
    for clean in remove_tags:
        tag = db.execute(select(Tag).where(Tag.name == clean)).scalar_one_or_none()
        if tag:
            db.execute(
                delete(IndicatorTag).where(
                    IndicatorTag.indicator_id == indicator.id, IndicatorTag.tag_id == tag.id
                )
            )
    if add_tags or remove_tags:
        changes["tags"] = {"added": add_tags, "removed": remove_tags}
    if "attack_ids" in payload.model_fields_set:
        db.execute(delete(IndicatorAttack).where(IndicatorAttack.indicator_id == indicator.id))
        attach_attack(db, indicator.id, payload.attack_ids)
        changes["attack_ids"] = payload.attack_ids
    if changes:
        db.flush()
        recompute_indicator(db, indicator)
        record_audit(
            db,
            "indicator.update",
            actor=user,
            object_type="indicator",
            object_id=indicator.id,
            detail={"value": indicator.value, "changes": changes},
            request=request,
        )
        db.commit()
    _notify_indicator(indicator)
    return {"data": indicator_detail(db, indicator, role=user.role)}


@router.post("/indicators/{indicator_id}/enrich")
def enrich(
    indicator_id: str,
    request: Request,
    force: bool = True,
    user: User = Depends(require("enrich")),
    db: Session = Depends(get_db),
):
    indicator = _get_indicator(db, indicator_id, user)
    result = enrich_indicator(db, indicator, force=force)
    record_audit(
        db,
        "indicator.enrich",
        actor=user,
        object_type="indicator",
        object_id=indicator.id,
        detail={"value": indicator.value, "result": result, "force": force},
        request=request,
    )
    db.commit()
    _notify_indicator(indicator)
    return {"data": indicator_detail(db, indicator, role=user.role), "meta": {"enrichment": result}}


@router.post("/indicators/{indicator_id}/relationships", status_code=201)
def create_relationship(
    indicator_id: str,
    payload: RelationshipCreate,
    request: Request,
    user: User = Depends(require("edit_indicators")),
    db: Session = Depends(get_db),
):
    indicator = _get_indicator(db, indicator_id, user)
    add_relationship(
        db,
        indicator,
        payload.target_value,
        payload.target_type or "",
        payload.relation_type,
        source_name=f"Analyst relationship · {user.name}",
        confidence=60,
        reliability=0.6,
        tlp=indicator.tlp,
        authorize=lambda existing: _get_indicator(db, existing.id, user),
    )
    record_audit(
        db,
        "indicator.relationship_create",
        actor=user,
        object_type="indicator",
        object_id=indicator.id,
        detail={"target": payload.target_value, "relation": payload.relation_type},
        request=request,
    )
    db.commit()
    return {"data": indicator_detail(db, indicator, role=user.role)}


@router.get("/indicators/{indicator_id}/graph")
def relationship_graph(
    indicator_id: str,
    depth: int = 2,
    user: User = Depends(require("view_indicators")),
    db: Session = Depends(get_db),
):
    root = _get_indicator(db, indicator_id, user)
    depth = max(1, min(3, depth))
    nodes = {root.id: root}
    edges: dict[str, dict] = {}
    frontier = {root.id}
    for _ in range(depth):
        if not frontier or len(nodes) >= 50:
            break
        rows = db.execute(
            select(IndicatorRelationship).where(
                (IndicatorRelationship.source_id.in_(frontier))
                | (IndicatorRelationship.target_id.in_(frontier))
            ).limit(200)
        ).scalars().all()
        next_frontier = set()
        for edge in rows:
            other_id = edge.target_id if edge.source_id in frontier else edge.source_id
            if other_id not in nodes and len(nodes) < 50:
                other = db.get(Indicator, other_id)
                if other and can_view_tlp(user.role, other.tlp):
                    nodes[other.id] = other
                    next_frontier.add(other.id)
            if other_id in nodes and edge.source_id in nodes and edge.target_id in nodes:
                edges[edge.id] = {
                    "id": edge.id,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "relation_type": edge.relation_type,
                    "confidence": edge.confidence,
                }
        frontier = next_frontier
    return {
        "data": {
            "nodes": indicator_list_items(db, list(nodes.values())),
            "edges": list(edges.values()),
            "root": root.id,
        }
    }


@router.get("/export/stix")
def export_stix(
    request: Request,
    user: User = Depends(require("export")),
    db: Session = Depends(get_db),
    severity_min: int | None = None,
    type: Annotated[list[str] | None, Query()] = None,
    status: str = "active",
):
    indicators = _collect_export(db, user, severity_min=severity_min, types=type, status=status)
    bundle = build_stix_bundle(db, indicators)
    record_audit(
        db,
        "export.stix",
        actor=user,
        object_type="export",
        detail={"count": len(indicators)},
        request=request,
    )
    db.commit()
    filename = f"threatlens-stix-{utcnow().date().isoformat()}.json"
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/stix+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/csv")
def export_csv_endpoint(
    request: Request,
    user: User = Depends(require("export")),
    db: Session = Depends(get_db),
    severity_min: int | None = None,
    type: Annotated[list[str] | None, Query()] = None,
    status: str = "active",
):
    indicators = _collect_export(db, user, severity_min=severity_min, types=type, status=status)
    content = "\ufeff" + export_csv(db, indicators)
    record_audit(
        db,
        "export.csv",
        actor=user,
        object_type="export",
        detail={"count": len(indicators)},
        request=request,
    )
    db.commit()
    filename = f"threatlens-indicators-{utcnow().date().isoformat()}.csv"
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _collect_export(
    db: Session,
    user: User,
    *,
    severity_min: int | None,
    types: list[str] | None,
    status: str,
) -> list[Indicator]:
    collected: list[Indicator] = []
    page = 1
    while len(collected) < 2000:
        result = search_indicators(
            db,
            role=user.role,
            types=types,
            severity_min=severity_min,
            status=status,
            page=page,
            size=100,
            sort="severity_desc",
        )
        collected.extend(result["items"])
        if len(result["items"]) < 100:
            break
        page += 1
    return collected[:2000]


def _lookup(
    db: Session,
    user: User,
    value: str,
    kind: str,
    request: Request,
    *,
    enrich_now: bool,
) -> dict:
    normalized = canonicalize(value, kind)
    if normalized is None:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_indicator", "message": "Invalid indicator value"},
        )
    canonical_value, indicator_type = normalized
    indicator = db.execute(
        select(Indicator).where(
            Indicator.value == canonical_value, Indicator.type == indicator_type
        )
    ).scalar_one_or_none()
    created = False
    if indicator is None:
        indicator, created = upsert_indicator(
            db,
            value=canonical_value,
            kind=indicator_type,
            source=f"Analyst lookup · {user.name}",
            confidence=40,
            reliability=0.5,
            tlp="amber",
            notes="Created by an authenticated reputation lookup.",
            malicious_ratio=0.25,
        )
    if indicator is not None:
        _get_indicator(db, indicator.id, user)
    result = enrich_indicator(db, indicator, force=enrich_now) if indicator else {}
    record_audit(
        db,
        "indicator.lookup",
        actor=user,
        object_type="indicator",
        object_id=indicator.id if indicator else None,
        detail={"value": canonical_value, "type": indicator_type, "created": created},
        request=request,
    )
    db.commit()
    return {"indicator": indicator_detail(db, indicator, role=user.role), "enrichment": result}


@router.get("/reputation/ip/{ip}")
def ip_reputation(
    ip: str,
    request: Request,
    refresh: bool = False,
    user: User = Depends(require("view_indicators")),
    db: Session = Depends(get_db),
):
    result = _lookup(db, user, ip, "ip", request, enrich_now=refresh)
    verdict = next((row for row in result["indicator"]["enrichments"] if row["kind"] == "verdict"), None)
    return {
        "data": {
            "ip": result["indicator"]["value"],
            "severity_score": result["indicator"]["severity_score"],
            "score_breakdown": result["indicator"]["score_breakdown"],
            "verdict": verdict,
            "enrichment": result["enrichment"],
            "indicator": result["indicator"],
        }
    }


@router.get("/hash/{sha256}")
def hash_lookup(
    sha256: str,
    request: Request,
    refresh: bool = False,
    user: User = Depends(require("view_indicators")),
    db: Session = Depends(get_db),
):
    result = _lookup(db, user, sha256, "hash_sha256", request, enrich_now=refresh)
    verdict = next((row for row in result["indicator"]["enrichments"] if row["kind"] == "verdict"), None)
    return {
        "data": {
            "hash": result["indicator"]["value"],
            "engine_verdicts": verdict,
            "severity_score": result["indicator"]["severity_score"],
            "enrichment": result["enrichment"],
            "indicator": result["indicator"],
        }
    }


@router.get("/domains/{domain}/analysis")
def domain_analysis(
    domain: str,
    request: Request,
    refresh: bool = False,
    user: User = Depends(require("view_indicators")),
    db: Session = Depends(get_db),
):
    result = _lookup(db, user, domain, "domain", request, enrich_now=refresh)
    verdict = next((row for row in result["indicator"]["enrichments"] if row["kind"] == "verdict"), None)
    return {
        "data": {
            "domain": result["indicator"]["value"],
            "verdict": verdict,
            "severity_score": result["indicator"]["severity_score"],
            "enrichment": result["enrichment"],
            "indicator": result["indicator"],
        }
    }

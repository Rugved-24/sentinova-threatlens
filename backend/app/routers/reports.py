from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..access import get_visible_incident, incident_visibility
from ..audit import record_audit
from ..db import get_db
from ..deps import require
from ..models import Incident, Report, User
from ..reporting import generate_report, report_path_safe
from ..schemas import ReportCreate
from ..security import has_permission, require_permission
from ..serializers import report_item

router = APIRouter(tags=["reports"])


@router.get("/reports")
def list_reports(
    user: User = Depends(require("generate_reports")),
    db: Session = Depends(get_db),
):
    visible_incidents = select(Incident.id).where(incident_visibility(user.role))
    query = select(Report).where(or_(
        Report.kind != "incident", Report.options["incident_id"].as_string().in_(visible_incidents),
    ))
    if not has_permission(user.role, "read_incidents"):
        query = query.where(Report.kind != "incident")
    if user.role not in {"admin", "engineer", "responder"}:
        query = query.where(or_(Report.requested_by == user.id, Report.requested_by.is_(None)))
    reports = db.execute(query.order_by(Report.created_at.desc()).limit(100)).scalars().all()
    return {"data": [report_item(report) for report in reports]}


@router.post("/reports", status_code=201)
def create_report(
    payload: ReportCreate,
    request: Request,
    user: User = Depends(require("generate_reports")),
    db: Session = Depends(get_db),
):
    if payload.kind == "incident":
        require_permission(user, "read_incidents")
        if not payload.incident_id:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "incident_required",
                    "message": "incident_id is required for incident reports",
                },
            )
        get_visible_incident(db, payload.incident_id, user)
    report = generate_report(
        db,
        user=user,
        title=payload.title,
        kind=payload.kind,
        incident_id=payload.incident_id,
    )
    record_audit(
        db,
        "report.generate",
        actor=user,
        object_type="report",
        object_id=report.id,
        detail={"title": report.title, "kind": report.kind, "status": report.status},
        request=request,
    )
    db.commit()
    return {"data": report_item(report)}


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    user: User = Depends(require("generate_reports")),
    db: Session = Depends(get_db),
):
    report = db.get(Report, report_id)
    if report is None or not report.storage_path:
        raise HTTPException(
            status_code=404, detail={"error_code": "not_found", "message": "Report not found"}
        )
    if report.kind == "incident":
        require_permission(user, "read_incidents")
        incident_id = (report.options or {}).get("incident_id")
        if not incident_id:
            raise HTTPException(403, detail={"error_code": "unclassified_report", "message": "Regenerate this report"})
        get_visible_incident(db, incident_id, user)
    if (
        report.requested_by not in {None, user.id}
        and user.role not in {"admin", "engineer", "responder"}
    ):
        raise HTTPException(
            status_code=403,
            detail={"error_code": "forbidden", "message": "Report belongs to another user"},
        )
    try:
        path: Path = report_path_safe(report.storage_path)
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error_code": "unsafe_path", "message": "Report path validation failed"},
        ) from exc
    if not path.exists():
        raise HTTPException(
            status_code=404, detail={"error_code": "file_missing", "message": "Report file missing"}
        )
    record_audit(
        db,
        "report.download",
        actor=user,
        object_type="report",
        object_id=report.id,
        request=request,
    )
    db.commit()
    safe_name = "".join(character for character in report.title if character.isalnum() or character in " -_")[:80]
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"{safe_name or 'threatlens-report'}.pdf",
    )

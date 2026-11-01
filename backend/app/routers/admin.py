from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import record_audit, verify_audit_chain
from ..db import get_db
from ..deps import require
from ..models import AuditLog, RefreshToken, User
from ..schemas import UserCreate, UserUpdate
from ..security import hash_password, password_policy_errors
from ..serializers import audit_item, user_public
from ..utils import utcnow

router = APIRouter(tags=["admin"])


@router.get("/users")
def list_users(
    user: User = Depends(require("manage_users")),
    db: Session = Depends(get_db),
):
    users = db.execute(select(User).order_by(User.created_at.asc())).scalars().all()
    return {"data": [user_public(row) for row in users]}


@router.post("/users", status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    user: User = Depends(require("manage_users")),
    db: Session = Depends(get_db),
):
    errors = password_policy_errors(payload.password)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "weak_password",
                "message": "Password must contain " + ", ".join(errors),
            },
        )
    created = User(
        email=payload.email.lower(),
        name=payload.name.strip(),
        role=payload.role,
        password_hash=hash_password(payload.password),
    )
    db.add(created)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={"error_code": "duplicate_email", "message": "Email already exists"},
        ) from exc
    record_audit(
        db,
        "user.create",
        actor=user,
        object_type="user",
        object_id=created.id,
        detail={"email": created.email, "role": created.role},
        request=request,
    )
    db.commit()
    return {"data": user_public(created)}


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    user: User = Depends(require("manage_users")),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail={"error_code": "not_found", "message": "User not found"})
    if target.id == user.id and (
        (payload.is_active is False) or (payload.role is not None and payload.role != "admin")
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "self_lockout",
                "message": "You cannot deactivate or demote your own administrator account",
            },
        )
    if target.role == "admin" and (payload.role not in {None, "admin"} or payload.is_active is False):
        admin_count = db.execute(
            select(func.count()).select_from(User).where(
                User.role == "admin", User.is_active.is_(True)
            )
        ).scalar_one()
        if admin_count <= 1:
            raise HTTPException(
                status_code=409,
                detail={
                    "error_code": "last_admin",
                    "message": "At least one active administrator must remain",
                },
            )
    changes = {}
    if payload.name is not None:
        target.name = payload.name.strip()
        changes["name"] = target.name
    if payload.role is not None:
        target.role = payload.role
        changes["role"] = payload.role
    if payload.is_active is not None:
        target.is_active = payload.is_active
        changes["is_active"] = payload.is_active
        if not payload.is_active:
            db.query(RefreshToken).filter(
                RefreshToken.user_id == target.id, RefreshToken.revoked.is_(False)
            ).update({RefreshToken.revoked: True})
    if payload.password is not None:
        errors = password_policy_errors(payload.password)
        if errors:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "weak_password",
                    "message": "Password must contain " + ", ".join(errors),
                },
            )
        target.password_hash = hash_password(payload.password)
        target.failed_attempts = 0
        target.locked_until = None
        db.query(RefreshToken).filter(
            RefreshToken.user_id == target.id, RefreshToken.revoked.is_(False)
        ).update({RefreshToken.revoked: True})
        changes["password"] = "reset"
    record_audit(
        db,
        "user.update",
        actor=user,
        object_type="user",
        object_id=target.id,
        detail={"email": target.email, "changes": changes},
        request=request,
    )
    db.commit()
    return {"data": user_public(target)}


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(
    user_id: str,
    request: Request,
    user: User = Depends(require("manage_users")),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail={"error_code": "not_found", "message": "User not found"})
    target.mfa_enabled = False
    target.mfa_secret_enc = None
    record_audit(
        db,
        "user.mfa_reset",
        actor=user,
        object_type="user",
        object_id=target.id,
        detail={"email": target.email},
        request=request,
    )
    db.commit()
    return {"data": user_public(target)}


@router.get("/audit")
def list_audit(
    user: User = Depends(require("view_audit")),
    db: Session = Depends(get_db),
    action: str | None = None,
    actor: str | None = None,
    page: int = 1,
    size: int = 50,
):
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action == action)
    if actor:
        query = query.where(AuditLog.actor_email.ilike(f"%{actor[:100]}%"))
    total = db.execute(select(func.count()).select_from(query.subquery())).scalar_one()
    size = max(1, min(200, size))
    rows = db.execute(
        query.order_by(AuditLog.id.desc()).offset((max(1, page) - 1) * size).limit(size)
    ).scalars().all()
    return {
        "data": [audit_item(row) for row in rows],
        "meta": {"total": total, "page": page, "size": size, "generated_at": utcnow().isoformat()},
    }


@router.get("/audit/verify")
def audit_verify(
    user: User = Depends(require("view_audit")),
    db: Session = Depends(get_db),
):
    return {"data": verify_audit_chain(db)}

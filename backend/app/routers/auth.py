from __future__ import annotations

from datetime import timedelta

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import record_audit
from ..config import get_settings
from ..db import get_db
from ..deps import get_current_user
from ..models import RefreshToken, User
from ..schemas import (
    ChangePassword,
    LoginIn,
    MfaDisable,
    MfaEnable,
    ProfileUpdate,
    TokenOut,
)
from ..security import (
    ACCESS_COOKIE,
    clear_refresh_cookie,
    client_ip,
    create_access_token,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    limiter,
    new_refresh_token,
    password_policy_errors,
    refresh_cookie,
    verify_password,
)
from ..serializers import user_public
from ..utils import sha256, utcnow

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()
DUMMY_HASH = hash_password("ThreatLens-Dummy-Password-2026!")


def _auth_error(message: str = "Invalid email or password", status_code: int = 401):
    raise HTTPException(
        status_code=status_code,
        detail={"error_code": "authentication_failed", "message": message},
    )


def _issue_session(db: Session, user: User, request: Request, response: Response) -> dict:
    access, expires_in = create_access_token(user.id, user.role)
    raw_refresh, refresh_hash = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=refresh_hash,
            expires_at=utcnow() + timedelta(days=settings.refresh_token_days),
            user_agent=request.headers.get("user-agent", "")[:255],
            ip=client_ip(request),
        )
    )
    user.last_login_at = utcnow()
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    refresh_cookie(response, raw_refresh)
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_public(user),
    }


@router.post("/login", response_model=TokenOut)
def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    allowed, retry_after = limiter.check(f"login:{ip}", settings.login_rate_limit, 60)
    email_key = payload.email.lower()
    email_allowed, email_retry = limiter.check(f"login:email:{email_key}", 6, 60)
    if not allowed or not email_allowed:
        raise HTTPException(
            status_code=429,
            detail={"error_code": "rate_limited", "message": "Too many login attempts"},
            headers={"Retry-After": str(max(retry_after, email_retry))},
        )
    user = db.execute(select(User).where(User.email == email_key)).scalar_one_or_none()
    if user is None:
        verify_password(DUMMY_HASH, payload.password)
        record_audit(
            db,
            "auth.login_failed",
            object_type="user",
            detail={"email": email_key, "reason": "unknown_account"},
            request=request,
        )
        db.commit()
        _auth_error()
    if not user.is_active:
        record_audit(
            db, "auth.login_failed", actor=user, detail={"reason": "inactive"}, request=request
        )
        db.commit()
        _auth_error("Account is disabled", 403)
    if user.locked_until and user.locked_until > utcnow():
        record_audit(
            db, "auth.login_failed", actor=user, detail={"reason": "locked"}, request=request
        )
        db.commit()
        _auth_error("Account temporarily locked. Try again later.", 423)
    if not verify_password(user.password_hash, payload.password):
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.locked_until = utcnow() + timedelta(minutes=15)
            user.failed_attempts = 0
        record_audit(
            db,
            "auth.login_failed",
            actor=user,
            detail={"reason": "bad_password", "lockout": bool(user.locked_until)},
            request=request,
        )
        db.commit()
        _auth_error()
    if user.mfa_enabled:
        if not payload.otp:
            _auth_error("Multi-factor code required", 401)
        if not user.mfa_secret_enc:
            _auth_error("Multi-factor configuration is incomplete", 403)
        try:
            secret = decrypt_secret(user.mfa_secret_enc)
        except ValueError:
            _auth_error("Multi-factor configuration is invalid", 403)
        if not pyotp.TOTP(secret).verify(payload.otp, valid_window=1):
            record_audit(
                db, "auth.login_failed", actor=user, detail={"reason": "bad_otp"}, request=request
            )
            db.commit()
            _auth_error("Invalid multi-factor code", 401)
    record_audit(
        db, "auth.login", actor=user, object_type="user", object_id=user.id, request=request
    )
    return _issue_session(db, user, request, response)


@router.post("/refresh", response_model=TokenOut)
def refresh_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    raw = request.cookies.get(ACCESS_COOKIE)
    if not raw:
        _auth_error("Refresh token missing", 401)
    token = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == sha256(raw))
    ).scalar_one_or_none()
    if token is None:
        clear_refresh_cookie(response)
        _auth_error("Refresh token is invalid", 401)
    if token.revoked:
        db.query(RefreshToken).filter(RefreshToken.user_id == token.user_id).update(
            {RefreshToken.revoked: True}
        )
        record_audit(
            db,
            "auth.refresh_reuse",
            object_type="user",
            object_id=token.user_id,
            detail={"reason": "revoked token reuse"},
            request=request,
        )
        db.commit()
        clear_refresh_cookie(response)
        _auth_error("Refresh token reuse detected; session revoked", 401)
    if token.expires_at < utcnow():
        token.revoked = True
        db.commit()
        clear_refresh_cookie(response)
        _auth_error("Refresh token expired", 401)
    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        clear_refresh_cookie(response)
        _auth_error("Account is not active", 401)
    token.revoked = True
    access, expires_in = create_access_token(user.id, user.role)
    new_raw, new_hash = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=new_hash,
            expires_at=utcnow() + timedelta(days=settings.refresh_token_days),
            user_agent=request.headers.get("user-agent", "")[:255],
            ip=client_ip(request),
        )
    )
    record_audit(
        db, "auth.refresh", actor=user, object_type="user", object_id=user.id, request=request
    )
    db.commit()
    refresh_cookie(response, new_raw)
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_public(user),
    }


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(ACCESS_COOKIE)
    if raw:
        token = db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == sha256(raw))
        ).scalar_one_or_none()
        if token:
            token.revoked = True
            user = db.get(User, token.user_id)
            record_audit(db, "auth.logout", actor=user, request=request)
            db.commit()
    clear_refresh_cookie(response)
    return Response(status_code=204)


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"data": user_public(user)}


@router.patch("/profile")
def update_profile(
    payload: ProfileUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.name is not None:
        user.name = payload.name.strip()
    if payload.preferences is not None:
        import json

        serialized = json.dumps(payload.preferences)
        if len(serialized) > 8000:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "preferences_too_large", "message": "Preferences exceed 8 KB"},
            )
        user.preferences = payload.preferences
    record_audit(
        db, "user.profile_update", actor=user, object_type="user", object_id=user.id, request=request
    )
    db.commit()
    return {"data": user_public(user)}


@router.post("/change-password")
def change_password(
    payload: ChangePassword,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(user.password_hash, payload.current_password):
        raise HTTPException(
            status_code=403,
            detail={"error_code": "invalid_password", "message": "Current password is incorrect"},
        )
    errors = password_policy_errors(payload.new_password)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "weak_password",
                "message": "Password must contain " + ", ".join(errors),
            },
        )
    user.password_hash = hash_password(payload.new_password)
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False)
    ).update({RefreshToken.revoked: True})
    record_audit(
        db,
        "auth.password_change",
        actor=user,
        object_type="user",
        object_id=user.id,
        request=request,
    )
    db.commit()
    return {"data": {"message": "Password changed. Sign in again."}}


@router.post("/mfa/setup")
def mfa_setup(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if user.mfa_enabled:
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "mfa_already_enabled",
                "message": "Disable MFA with your password and current code before re-enrolling",
            },
        )
    secret = pyotp.random_base32()
    user.mfa_secret_enc = encrypt_secret(secret)
    user.mfa_enabled = False
    record_audit(
        db, "auth.mfa_setup", actor=user, object_type="user", object_id=user.id, request=request
    )
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Sentinova ThreatLens")
    return {"data": {"secret": secret, "otpauth_url": uri}}


@router.post("/mfa/enable")
def mfa_enable(
    payload: MfaEnable,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not user.mfa_secret_enc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": "mfa_not_initialised", "message": "Start MFA setup first"},
        )
    secret = decrypt_secret(user.mfa_secret_enc)
    if not pyotp.TOTP(secret).verify(payload.code, valid_window=1):
        raise HTTPException(
            status_code=400,
            detail={"error_code": "invalid_otp", "message": "Invalid authenticator code"},
        )
    user.mfa_enabled = True
    if user.role == "admin":
        db.query(RefreshToken).filter(
            RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False)
        ).update({RefreshToken.revoked: True})
    record_audit(
        db, "auth.mfa_enable", actor=user, object_type="user", object_id=user.id, request=request
    )
    db.commit()
    return {"data": {"mfa_enabled": True}}


@router.post("/mfa/disable")
def mfa_disable(
    payload: MfaDisable,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not user.mfa_enabled or not user.mfa_secret_enc:
        return {"data": {"mfa_enabled": False}}
    if not verify_password(user.password_hash, payload.password):
        raise HTTPException(
            status_code=403,
            detail={"error_code": "invalid_password", "message": "Password is incorrect"},
        )
    secret = decrypt_secret(user.mfa_secret_enc)
    if not pyotp.TOTP(secret).verify(payload.code, valid_window=1):
        raise HTTPException(
            status_code=400,
            detail={"error_code": "invalid_otp", "message": "Invalid authenticator code"},
        )
    user.mfa_enabled = False
    user.mfa_secret_enc = None
    record_audit(
        db, "auth.mfa_disable", actor=user, object_type="user", object_id=user.id, request=request
    )
    db.commit()
    return {"data": {"mfa_enabled": False}}

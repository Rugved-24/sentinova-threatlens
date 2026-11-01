from __future__ import annotations

import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..db import SessionLocal
from ..events import manager
from ..models import User
from ..security import decode_access_token

logger = logging.getLogger("threatlens.ws")
router = APIRouter(tags=["realtime"])

ALLOWED_TOPIC_PREFIXES = ("alerts.", "indicators.", "incidents.", "system.", "user.")


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = ""):
    try:
        payload = decode_access_token(token)
    except Exception:
        await websocket.accept()
        await websocket.close(code=4401, reason="Invalid or expired token")
        return
    db = SessionLocal()
    try:
        user = db.get(User, payload["sub"])
        if user is None or not user.is_active:
            await websocket.accept()
            await websocket.close(code=4401, reason="Account is not active")
            return
    finally:
        db.close()
    await manager.connect(websocket, user.id, user.role, expires_at=payload["exp"])
    try:
        await websocket.send_json(
            {
                "topic": "system.ready",
                "data": {"user_id": user.id, "role": user.role, "message": "ThreatLens live feed connected"},
            }
        )
        while True:
            message = await websocket.receive_json()
            with SessionLocal() as db:
                current_user = db.get(User, user.id)
                if not current_user or not current_user.is_active or payload["exp"] <= time.time():
                    await websocket.close(code=4401, reason="Session expired or account disabled")
                    break
            action = message.get("action")
            if action == "subscribe":
                topics = [
                    str(topic)[:64]
                    for topic in (message.get("topics") or [])
                    if str(topic).startswith(ALLOWED_TOPIC_PREFIXES)
                    and (
                        not str(topic).startswith("user.")
                        or str(topic) == f"user.{user.id}"
                    )
                ][:20]
                topics = manager.subscribe(websocket, topics)
                await websocket.send_json({"topic": "system.subscribed", "data": {"topics": topics}})
            elif action == "ping":
                await websocket.send_json({"topic": "pong", "data": {}})
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket handler failed")
    finally:
        manager.disconnect(websocket)

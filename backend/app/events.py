from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any

from fastapi import WebSocket

from .access import event_allowed, topic_allowed
from .config import get_settings
from .db import SessionLocal
from .models import User
from .utils import iso, utcnow

logger = logging.getLogger("threatlens.events")
settings = get_settings()
CHANNEL = "threatlens.events"


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[WebSocket, dict[str, Any]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._redis = None
        self._redis_task: asyncio.Task | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: WebSocket, user_id: str, role: str, *, expires_at: float) -> None:
        await websocket.accept()
        self._connections[websocket] = {
            "user_id": user_id, "role": role, "expires_at": expires_at, "topics": set(),
        }
        self.subscribe(websocket, [])

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.pop(websocket, None)

    def subscribe(self, websocket: WebSocket, topics: list[str]) -> list[str]:
        state = self._connections.get(websocket)
        if not state or state["expires_at"] <= time.time():
            return []
        requested = set(topics) | {"alerts.stream", "system.health", f"user.{state['user_id']}"}
        with SessionLocal() as db:
            user = db.get(User, state["user_id"])
            approved = {topic for topic in requested if topic_allowed(db, user, topic)}
        state["topics"] = approved
        return sorted(approved)

    async def _send(self, topic: str, payload: dict[str, Any]) -> None:
        # Details are fetched through the authorized REST API after invalidation.
        message = {"topic": topic, "ts": iso(utcnow()), "data": {"changed": True}}
        stale: list[WebSocket] = []
        for websocket, state in list(self._connections.items()):
            with SessionLocal() as db:
                user = db.get(User, state["user_id"])
                expired = state["expires_at"] <= time.time() or not user or not user.is_active
                allowed = not expired and topic in state["topics"] and event_allowed(db, user, topic, payload)
            try:
                if expired:
                    await websocket.close(code=4401, reason="Session expired or account disabled")
                    stale.append(websocket)
                elif allowed:
                    await websocket.send_json(message)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)

    async def start_redis(self) -> bool:
        if not settings.redis_url:
            return False
        try:
            from redis.asyncio import Redis

            self._redis = Redis.from_url(settings.redis_url, decode_responses=True)
            await self._redis.ping()
            self._redis_task = asyncio.create_task(self._listen())
            logger.info("Redis event bus connected")
            return True
        except Exception:
            logger.exception("Redis event bus unavailable; using in-process delivery")
            self._redis = None
            return False

    async def _listen(self) -> None:
        if self._redis is None:
            return
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(CHANNEL)
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    envelope = json.loads(message["data"])
                    await self._send(str(envelope["topic"]), envelope.get("data") or {})
                except Exception:
                    logger.exception("Malformed Redis event")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Redis event listener stopped")
        finally:
            await pubsub.close()

    async def stop_redis(self) -> None:
        if self._redis_task:
            self._redis_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._redis_task
            self._redis_task = None
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    async def _publish_redis(self, topic: str, payload: dict[str, Any]) -> None:
        if self._redis is None:
            await self._send(topic, payload)
            return
        try:
            await self._redis.publish(CHANNEL, json.dumps({"topic": topic, "data": payload}))
        except Exception:
            logger.exception("Redis publish failed; delivering locally")
            await self._send(topic, payload)

    def publish(self, topic: str, payload: dict[str, Any]) -> None:
        if not self._loop or not self._loop.is_running():
            if settings.redis_url:
                try:
                    from redis import Redis

                    with Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2) as publisher:
                        publisher.publish(CHANNEL, json.dumps({"topic": topic, "data": payload}))
                except Exception:
                    logger.exception("Worker could not publish live update to Redis")
            else:
                logger.warning("Live update skipped: no event loop or Redis configured")
            return
        if self._redis is not None:
            asyncio.run_coroutine_threadsafe(self._publish_redis(topic, payload), self._loop)
        else:
            asyncio.run_coroutine_threadsafe(self._send(topic, payload), self._loop)

    @property
    def count(self) -> int:
        return len(self._connections)


manager = ConnectionManager()

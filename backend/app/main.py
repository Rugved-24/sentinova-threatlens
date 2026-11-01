from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import FRONTEND_DIST, get_settings
from .context import correlation_id
from .db import init_db
from .events import manager
from .jobs import start_scheduler, stop_scheduler
from .logging_setup import configure_logging
from .routers import admin, alerts, auth, dashboards, feeds, hooks, incidents, indicators, reports, search, system, ws
from .security import client_ip, limiter
from .seed import ensure_seed
from .utils import iso, utcnow

settings = get_settings()
logger = logging.getLogger("threatlens.main")
configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    manager.bind_loop(asyncio.get_running_loop())
    await manager.start_redis()
    if os.getenv("THREATLENS_SKIP_SEED") != "1":
        ensure_seed()
    if settings.search_backend == "elasticsearch":
        try:
            from .db import SessionLocal
            from .indexing import ensure_indices, rebuild_all

            ensure_indices()
            if os.getenv("THREATLENS_REBUILD_INDEX") == "1":
                with SessionLocal() as db:
                    indexed = rebuild_all(db)
                logger.info("Rebuilt Elasticsearch projection with %s documents", indexed)
        except Exception:
            logger.exception("Elasticsearch projection is unavailable; using SQL search fallback")
    if settings.run_scheduler:
        start_scheduler()
    logger.info("ThreatLens %s started in %s mode", __version__, settings.app_env)
    yield
    stop_scheduler()
    await manager.stop_redis()
    logger.info("ThreatLens stopped")


app = FastAPI(
    title="Sentinova ThreatLens",
    version=__version__,
    description=(
        "Cyber Threat Intelligence Dashboard — IOC aggregation, transparent scoring, "
        "internal correlation, ATT&CK mapping, incident response and STIX/TAXII exchange."
    ),
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-ThreatLens-Signature", "X-ThreatLens-Timestamp"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id", "")
    try:
        request_id = str(uuid.UUID(request_id)) if request_id else str(uuid.uuid4())
    except ValueError:
        request_id = str(uuid.uuid4())
    token = correlation_id.set(request_id)
    path = request.url.path
    try:
        if path.startswith("/api/") and path not in {"/api/v1/health", "/api/v1/metrics"}:
            ip = client_ip(request)
            allowed, retry_after = limiter.check(
                f"global:{ip}", settings.rate_limit_per_minute, 60
            )
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error_code": "rate_limited",
                        "message": "Request rate exceeded; slow down and retry",
                        "correlation_id": request_id,
                    },
                    headers={"Retry-After": str(retry_after), "X-Request-ID": request_id},
                )
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > settings.max_request_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error_code": "payload_too_large",
                            "message": "Request body exceeds the configured limit",
                            "correlation_id": request_id,
                        },
                        headers={"X-Request-ID": request_id},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error_code": "invalid_content_length",
                        "message": "Malformed Content-Length header",
                        "correlation_id": request_id,
                    },
                    headers={"X-Request-ID": request_id},
                )
        response = await call_next(request)
    finally:
        correlation_id.reset(token)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if not settings.is_dev or settings.cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if path != "/api/docs" and not path.startswith("/api/redoc"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self' ws: wss:; font-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    return response


def _error(status_code: int, code: str, message: str, request_id: str, errors=None):
    body = {"error_code": code, "message": message, "correlation_id": request_id}
    if errors:
        body["errors"] = errors
    return JSONResponse(status_code=status_code, content=body, headers={"X-Request-ID": request_id})


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    request_id = correlation_id.get()
    if isinstance(detail, dict):
        code = detail.get("error_code", "http_error")
        message = detail.get("message", str(detail))
    else:
        code = "http_error"
        message = str(detail)
    return _error(exc.status_code, code, message, request_id)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for error in exc.errors()[:20]:
        errors.append(
            {
                "field": ".".join(str(part) for part in error.get("loc", [])[1:]),
                "message": error.get("msg", "Invalid value"),
                "type": error.get("type", "validation_error"),
            }
        )
    return _error(422, "validation_error", "Request validation failed", correlation_id.get(), errors)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return _error(
        500,
        "internal_error",
        "An internal error occurred. Reference the correlation ID when reporting.",
        correlation_id.get(),
    )


API = "/api/v1"
app.include_router(auth.router, prefix=API)
app.include_router(indicators.router, prefix=API)
app.include_router(search.router, prefix=API)
app.include_router(alerts.router, prefix=API)
app.include_router(incidents.router, prefix=API)
app.include_router(dashboards.router, prefix=API)
app.include_router(feeds.router, prefix=API)
app.include_router(reports.router, prefix=API)
app.include_router(admin.router, prefix=API)
app.include_router(system.router, prefix=API)
app.include_router(hooks.router, prefix=API)
app.include_router(ws.router, prefix=API)


@app.get("/api")
def api_root():
    return {
        "name": "Sentinova ThreatLens",
        "version": __version__,
        "docs": "/api/docs",
        "health": "/api/v1/health",
        "time": iso(utcnow()),
    }


if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            return _error(404, "not_found", "Endpoint not found", correlation_id.get())
        dist = FRONTEND_DIST.resolve()
        candidate = (dist / full_path).resolve()
        if full_path and dist in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        index = dist / "index.html"
        if index.exists():
            return FileResponse(index)
        return _error(404, "not_found", "Frontend build not found", correlation_id.get())

else:

    @app.get("/", include_in_schema=False)
    def no_frontend():
        return {
            "message": "ThreatLens API is running. Build the frontend with 'npm run build' in frontend/.",
            "docs": "/api/docs",
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.getenv("THREATLENS_HOST", "127.0.0.1"),
        port=int(os.getenv("THREATLENS_PORT", "8000")),
        reload=False,
    )

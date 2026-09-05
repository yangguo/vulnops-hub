from __future__ import annotations

import time

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from vulnops import __version__
from vulnops.config import get_settings

router = APIRouter(tags=["health"])

_START_TIME = time.monotonic()


def _service_payload() -> dict:
    settings = get_settings()
    return {
        "service": settings.app_name,
        "version": settings.app_version or __version__,
        "status": "ok",
    }


@router.get("/health/live", summary="Liveness probe")
async def liveness(request: Request) -> JSONResponse:
    payload = _service_payload()
    # X-Request-ID is added by middleware; echo it in body for convenience
    payload["request_id"] = request.headers.get("X-Request-ID") or getattr(
        request.state, "request_id", ""
    )
    resp = JSONResponse(payload)
    # middleware already sets header, but be defensive
    if hasattr(request.state, "request_id"):
        resp.headers["X-Request-ID"] = request.state.request_id
    return resp


@router.get("/health/ready", summary="Readiness probe")
async def readiness(request: Request) -> JSONResponse:
    settings = get_settings()
    checks: dict[str, str] = {}
    overall_ok = True

    # Database connectivity check - never leak credentials or traceback
    try:
        # Use sync engine with short timeout; support sqlite & postgres
        from sqlalchemy import create_engine, text

        url = settings.effective_database_url
        # For sqlite we need connect_args, for postgres timeout
        connect_args = {}
        if url.startswith("sqlite"):
            # sqlite check: create engine and execute SELECT 1
            engine = create_engine(url, connect_args={"check_same_thread": False})
        else:
            engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 2})

        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.commit()
        engine.dispose()
        checks["database"] = "ok"
    except Exception:
        # Do not expose exception text, type, or DSN
        checks["database"] = "degraded"
        overall_ok = False

    # Queue check (optional) - only if configured
    if settings.effective_redis_url:
        try:
            import redis  # type: ignore

            r = redis.from_url(settings.effective_redis_url, socket_connect_timeout=1)
            r.ping()
            checks["queue"] = "ok"
        except Exception:
            checks["queue"] = "degraded"
            # queue degraded is not fatal for readiness in dev, but mark checks
            # For production you might want overall_ok=False; keep ok for now
            checks["queue"] = "degraded"

    payload = {
        **_service_payload(),
        "checks": checks,
        "uptime_seconds": round(time.monotonic() - _START_TIME, 3),
        "request_id": getattr(request.state, "request_id", ""),
    }

    status_code = 200 if overall_ok else 503
    resp = JSONResponse(payload, status_code=status_code)
    if hasattr(request.state, "request_id"):
        resp.headers["X-Request-ID"] = request.state.request_id
    # Ensure generic response does not contain sensitive substrings
    return resp


@router.get("/api/v1/health", include_in_schema=False)
async def legacy_health(request: Request) -> JSONResponse:
    # Compatibility alias
    return await liveness(request)

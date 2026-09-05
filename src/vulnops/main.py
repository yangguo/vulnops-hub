from __future__ import annotations

import uuid
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vulnops import __version__
from vulnops.api.health import router as health_router
from vulnops.config import get_settings

logger = logging.getLogger("vulnops")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info("starting vulnops-hub version=%s env=%s", settings.app_version, settings.environment)
    yield
    logger.info("shutting down vulnops-hub")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="VulnOps Hub",
        version=settings.app_version or __version__,
        description="Vulnerability-operations control plane — modular monolith",
        lifespan=lifespan,
    )

    # Request ID middleware - must run early
    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        # also store correlation id for later audit use
        request.state.correlation_id = request.headers.get("X-Correlation-ID") or request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        return response

    # Global error handler - never leak internal details
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Log with request_id for ops, but return generic to client
        req_id = getattr(request.state, "request_id", "-")
        logger.exception("unhandled error request_id=%s path=%s", req_id, request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "type": "https://hub.example/problems/internal-error",
                "title": "Internal Server Error",
                "status": 500,
                "code": "internal_error",
                "detail": "An unexpected error occurred.",
                "correlation_id": req_id,
            },
            headers={"X-Request-ID": req_id},
        )

    # Routers
    app.include_router(health_router)

    # Placeholder for future routers - imported lazily to avoid circular deps
    # They will be included here once modules exist:
    # from vulnops.api.sboms import router as sbom_router
    # app.include_router(sbom_router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        return {
            "service": settings.app_name,
            "version": settings.app_version or __version__,
            "docs": "/docs",
            "health": "/health/live",
        }

    return app


# For uvicorn direct import: `uvicorn vulnops.main:app`
app = create_app()

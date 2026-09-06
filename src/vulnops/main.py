from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from vulnops import __version__
from vulnops.api.health import router as health_router
from vulnops.auth.dependencies import (
    AuthenticationError,
    AuthorizationError,
    build_oidc_verifier,
    build_test_principal,
    get_principal,
    validate_auth_configuration,
)
from vulnops.config import get_settings

logger = logging.getLogger("vulnops")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = app.state.settings
    logger.info(
        "starting vulnops-hub version=%s env=%s", settings.app_version, settings.environment
    )
    try:
        yield
    finally:
        verifier = getattr(app.state, "oidc_verifier", None)
        close_verifier = getattr(verifier, "close", None)
        if callable(close_verifier):
            close_verifier()
        logger.info("shutting down vulnops-hub")


def create_app() -> FastAPI:
    settings = get_settings()
    validate_auth_configuration(settings)
    app = FastAPI(
        title="VulnOps Hub",
        version=settings.app_version or __version__,
        description="Vulnerability-operations control plane — modular monolith",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.test_principal = build_test_principal(settings)
    app.state.oidc_verifier = build_oidc_verifier(settings)

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

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(request: Request, exc: AuthenticationError):
        req_id = getattr(request.state, "request_id", "-")
        correlation_id = getattr(request.state, "correlation_id", req_id)
        detail = (
            "Authentication credentials were not provided."
            if exc.code == "authentication_required"
            else "The bearer token is invalid or expired."
        )
        return JSONResponse(
            status_code=401,
            content={
                "type": f"https://hub.example/problems/{exc.code}",
                "title": "Authentication Required"
                if exc.code == "authentication_required"
                else "Invalid Token",
                "status": 401,
                "code": exc.code,
                "detail": detail,
                "correlation_id": correlation_id,
            },
            headers={
                "WWW-Authenticate": "Bearer",
                "X-Request-ID": req_id,
                "X-Correlation-ID": correlation_id,
            },
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(request: Request, exc: AuthorizationError):
        req_id = getattr(request.state, "request_id", "-")
        correlation_id = getattr(request.state, "correlation_id", req_id)
        if exc.code == "resource_not_found":
            title = "Resource Not Found"
            detail = "The requested resource was not found."
        else:
            title = "Insufficient Permission"
            detail = "The authenticated principal lacks the required capability."
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": f"https://hub.example/problems/{exc.code}",
                "title": title,
                "status": exc.status_code,
                "code": exc.code,
                "detail": detail,
                "correlation_id": correlation_id,
            },
            headers={
                "X-Request-ID": req_id,
                "X-Correlation-ID": correlation_id,
            },
        )

    # Routers
    app.include_router(health_router)
    try:
        from vulnops.api.sboms import router as sbom_router

        app.include_router(sbom_router, prefix="/api/v1", dependencies=[Depends(get_principal)])
    except Exception as e:
        logger.warning("sbom router not loaded: %s", e)
    try:
        from vulnops.api.cases import router as cases_router

        app.include_router(cases_router, prefix="/api/v1", dependencies=[Depends(get_principal)])
    except Exception as e:
        logger.warning("cases router not loaded: %s", e)

    from vulnops.api.frontend import frontend_index_response

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        index = frontend_index_response()
        if index is not None:
            return index
        return {
            "service": settings.app_name,
            "version": settings.app_version or __version__,
            "docs": "/docs",
            "health": "/health/live",
        }

    from vulnops.api.frontend import mount_frontend

    mount_frontend(app)
    return app


# For uvicorn direct import: `uvicorn vulnops.main:app`
app = create_app()

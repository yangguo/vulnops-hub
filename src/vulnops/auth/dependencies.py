"""FastAPI authentication boundary.

Only this module knows how an HTTP request becomes a trusted ``Principal``.
The verifier validates the token before claims are mapped, and all failures
are converted to safe Problem Details responses by the application boundary.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from vulnops.auth.models import Principal, PrincipalType
from vulnops.auth.oidc import OIDCVerificationError, OIDCVerifier
from vulnops.config import Settings

logger = logging.getLogger("vulnops.auth")

_AUTHENTICATION_CODES = frozenset({"authentication_required", "invalid_token"})
_AUTHORIZATION_CODES = frozenset({"insufficient_permission", "resource_not_found"})
_BEARER_SCHEME = HTTPBearer(
    auto_error=False,
    bearerFormat="JWT",
    scheme_name="BearerAuth",
    description="OIDC access token",
)


class AuthenticationConfigurationError(RuntimeError):
    """Raised when startup would create an unauthenticated deployment."""


class AuthenticationError(Exception):
    """Safe request authentication failure.

    The exception stores only a stable public code.  It deliberately does not
    retain the bearer token, authorization header, raw claims, or provider
    exception text.
    """

    def __init__(self, code: str) -> None:
        if code not in _AUTHENTICATION_CODES:
            code = "invalid_token"
        self.code = code
        super().__init__(code)


class AuthorizationError(Exception):
    """Safe request authorization failure.

    Organization membership is checked before capabilities so callers outside
    an organization receive the same not-found response for every operation.
    The exception carries only a stable public code; request paths and claims
    are deliberately left to the application logging boundary.
    """

    def __init__(self, code: str) -> None:
        if code not in _AUTHORIZATION_CODES:
            code = "insufficient_permission"
        self.code = code
        self.status_code = 404 if code == "resource_not_found" else 403
        super().__init__(code)


def validate_auth_configuration(settings: Settings) -> None:
    """Validate startup authentication invariants before routes are served."""

    bypass_enabled = bool(settings.auth_test_bypass_enabled)
    if bypass_enabled and settings.environment != "test":
        raise AuthenticationConfigurationError(
            "AUTH_TEST_BYPASS_ENABLED requires ENVIRONMENT=test; test bypass is not allowed"
        )

    # A test-only bypass is the sole configuration allowed to run without an
    # issuer.  Every real deployment, including development, must fail closed.
    if not bypass_enabled and (not settings.oidc_issuer_url or not settings.oidc_audience):
        raise AuthenticationConfigurationError(
            "OIDC_ISSUER_URL and OIDC_AUDIENCE are required when test bypass is disabled"
        )


def build_oidc_verifier(settings: Settings) -> OIDCVerifier | None:
    """Construct one process-scoped verifier for an authenticated app."""

    if settings.auth_test_bypass_enabled:
        return None
    try:
        return OIDCVerifier.from_settings(settings)
    except OIDCVerificationError as exc:
        raise AuthenticationConfigurationError("invalid OIDC authentication configuration") from exc


def build_test_principal(settings: Settings) -> Principal:
    """Return the explicit, clearly marked principal used only by test bypass."""

    return Principal(
        subject=settings.auth_test_principal_subject,
        principal_type=PrincipalType.HUMAN,
    )


def _extract_bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthenticationError("invalid_token")
    return parts[1].strip()


def _claim_principal_type(claims: Mapping[str, Any], claim_name: str) -> PrincipalType:
    value = claims.get(claim_name)
    if not isinstance(value, str):
        raise AuthenticationError("invalid_token")
    normalized = value.strip().lower()
    try:
        return PrincipalType(normalized)
    except ValueError:
        raise AuthenticationError("invalid_token") from None


def principal_from_claims(claims: Mapping[str, Any], settings: Settings) -> Principal:
    """Map already-verified claims into an immutable trusted principal.

    Service tokens intentionally discard the role claim.  Even if a provider
    accidentally includes ``roles=admin`` on a client-credentials token, no
    downstream consumer can mistake those roles for human authorization.
    """

    if not isinstance(claims, Mapping):
        raise AuthenticationError("invalid_token")
    principal_type = _claim_principal_type(claims, settings.oidc_principal_type_claim)
    roles: Any = ()
    if principal_type is PrincipalType.HUMAN:
        roles = claims.get(settings.oidc_role_claim, ())
    try:
        return Principal(
            subject=claims.get("sub", ""),
            principal_type=principal_type,
            organization_ids=claims.get(settings.oidc_organization_claim, ()),
            roles=roles,
            scopes=claims.get(settings.oidc_service_scope_claim, ()),
            permissions=claims.get("permissions", ()),
        )
    except (TypeError, ValueError):
        raise AuthenticationError("invalid_token") from None


async def get_principal(
    request: Request,
    _credentials: HTTPAuthorizationCredentials | None = Security(_BEARER_SCHEME),
) -> Principal:
    """Authenticate one API request and return its immutable principal."""

    settings: Settings = request.app.state.settings
    if settings.auth_test_bypass_enabled:
        return request.app.state.test_principal

    token = _extract_bearer_token(request.headers.get("Authorization"))
    if token is None:
        raise AuthenticationError("authentication_required")

    verifier: OIDCVerifier | None = request.app.state.oidc_verifier
    if verifier is None:
        # This is an application wiring error, but never expose that detail to
        # callers or turn it into an unauthenticated request.
        logger.error("OIDC verifier missing from authenticated application state")
        raise AuthenticationError("invalid_token")

    try:
        claims = verifier.verify_token(token)
    except OIDCVerificationError as exc:
        logger.info("OIDC token rejected category=%s", exc.category)
        raise AuthenticationError("invalid_token") from None
    except Exception:
        # Provider/client exceptions can vary and may include sensitive input;
        # map them to the same safe public category without logging the value.
        logger.info("OIDC token rejected by verifier")
        raise AuthenticationError("invalid_token") from None

    return principal_from_claims(claims, settings)


def _is_explicit_test_bypass(request: Request, principal: Principal) -> bool:
    """Allow the configured test principal to exercise all organizations.

    This branch is tied to the application-created principal object and the
    startup-validated test bypass setting.  A real token containing ``*`` in
    its organization claim can never enter this branch.
    """

    settings: Settings = request.app.state.settings
    return bool(settings.auth_test_bypass_enabled) and principal is getattr(
        request.app.state, "test_principal", None
    )


async def require_organization(
    org_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
) -> Principal:
    """Require trusted membership in the organization path parameter."""

    if _is_explicit_test_bypass(request, principal):
        return principal
    # ``*`` is never a valid organization grant.  A real token containing a
    # wildcard claim must not turn into a global principal, including when a
    # caller mirrors that wildcard into the path parameter.
    if org_id.strip() == "*" or "*" in principal.organization_ids:
        raise AuthorizationError("resource_not_found")
    if not principal.has_organization(org_id):
        raise AuthorizationError("resource_not_found")
    return principal


def require_capability(capability: str):
    """Build a route dependency enforcing organization scope then capability."""

    normalized = capability.strip().lower()
    if not normalized:
        raise ValueError("capability must not be empty")

    async def dependency(
        request: Request,
        principal: Principal = Depends(require_organization),
    ) -> Principal:
        return authorize_capability(request, principal, normalized)

    dependency.__name__ = f"require_{normalized.replace(':', '_')}"
    return dependency


def authorize_capability(request: Request, principal: Principal, capability: str) -> Principal:
    """Authorize a trusted principal after a resource has been resolved.

    Resource routes call this helper only after checking ownership.  Keeping
    the capability check separate from the organization dependency prevents a
    cross-organization resource from leaking a 403, validation, or concurrency
    response before the route can return its safe 404.
    """

    normalized = capability.strip().lower()
    if not normalized:
        raise ValueError("capability must not be empty")
    if _is_explicit_test_bypass(request, principal):
        return principal
    if not principal.has_capability(normalized):
        raise AuthorizationError("insufficient_permission")
    return principal

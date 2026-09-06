from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from vulnops.auth.dependencies import AuthenticationError, principal_from_claims
from vulnops.auth.oidc import OIDCVerificationError
from vulnops.config import get_settings
from vulnops.main import create_app


class StubVerifier:
    def __init__(self, claims: dict[str, Any] | None = None) -> None:
        self.claims = claims or {
            "iss": "https://issuer.example",
            "aud": "vulnops-api",
            "exp": 4_000_000_000,
            "sub": "user-123",
            "principal_type": "human",
            "organizations": ["acme"],
            "roles": ["viewer"],
        }
        self.calls: list[str] = []

    def verify_token(self, token: str) -> dict[str, Any]:
        self.calls.append(token)
        if token == "expired-token":
            raise OIDCVerificationError("expired")
        return dict(self.claims)


def _configured_app(monkeypatch: pytest.MonkeyPatch, verifier: StubVerifier | None = None):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()
    app = create_app()
    if verifier is not None:
        app.state.oidc_verifier = verifier
    return app


def test_missing_bearer_token_returns_problem_details_401(monkeypatch: pytest.MonkeyPatch):
    client = TestClient(_configured_app(monkeypatch))

    response = client.get("/api/v1/organizations/acme/cases")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    body = response.json()
    assert body["status"] == 401
    assert body["code"] == "authentication_required"
    assert body["correlation_id"]
    assert "detail" in body


def test_malformed_bearer_token_returns_safe_problem_details(monkeypatch: pytest.MonkeyPatch):
    client = TestClient(_configured_app(monkeypatch))
    marker = "secret-malformed-token"

    response = client.get(
        "/api/v1/organizations/acme/cases",
        headers={"Authorization": f"Basic {marker}"},
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["code"] == "invalid_token"
    assert marker not in response.text


def test_malformed_bearer_scheme_returns_safe_problem_details(monkeypatch: pytest.MonkeyPatch):
    client = TestClient(_configured_app(monkeypatch))

    response = client.get(
        "/api/v1/organizations/acme/cases",
        headers={"Authorization": "Bearer"},
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["code"] == "invalid_token"


def test_expired_bearer_token_returns_safe_invalid_token(monkeypatch: pytest.MonkeyPatch):
    verifier = StubVerifier()
    client = TestClient(_configured_app(monkeypatch, verifier))

    response = client.get(
        "/api/v1/organizations/acme/cases",
        headers={"Authorization": "Bearer expired-token"},
    )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["code"] == "invalid_token"
    assert "expired provider error" not in response.text


def test_valid_bearer_token_authenticates_business_route(monkeypatch: pytest.MonkeyPatch):
    verifier = StubVerifier()
    client = TestClient(_configured_app(monkeypatch, verifier))

    response = client.get(
        "/api/v1/organizations/acme/cases",
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200, response.text
    assert verifier.calls == ["valid-token"]


def test_service_claim_mapper_discards_human_roles(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()
    settings = get_settings()

    principal = principal_from_claims(
        {
            "sub": "ci-release",
            "principal_type": "service",
            "organizations": ["acme"],
            "roles": ["admin", "risk_approver"],
            "scope": "sbom:write",
        },
        settings,
    )

    assert principal.is_service
    assert principal.roles == frozenset()
    assert principal.has_capability("sbom:write")
    assert not principal.has_capability("risk:approve")


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "missing-type"},
        {"sub": "unknown-type", "principal_type": "client"},
        {"sub": "wrong-type", "principal_type": 1},
    ],
)
def test_claim_mapper_requires_explicit_human_or_service_type(
    monkeypatch: pytest.MonkeyPatch, claims: dict[str, Any]
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()

    with pytest.raises(AuthenticationError, match="invalid_token"):
        principal_from_claims(claims, get_settings())


def test_claim_mapper_uses_configured_required_type_claim(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    monkeypatch.setenv("OIDC_PRINCIPAL_TYPE_CLAIM", "kind")
    get_settings.cache_clear()

    principal = principal_from_claims(
        {
            "sub": "ci-release",
            "kind": "service",
            "roles": ["admin"],
            "scope": "sbom:write",
        },
        get_settings(),
    )

    assert principal.is_service
    assert principal.roles == frozenset()


class LifecycleVerifier(StubVerifier):
    def __init__(self) -> None:
        super().__init__()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


def test_verifier_is_app_scoped_and_closed_with_lifespan(monkeypatch: pytest.MonkeyPatch):
    verifier = LifecycleVerifier()
    factory_calls: list[Any] = []

    def build_verifier(settings: Any) -> LifecycleVerifier:
        factory_calls.append(settings)
        return verifier

    monkeypatch.setattr("vulnops.main.build_oidc_verifier", build_verifier)
    app = _configured_app(monkeypatch)

    with TestClient(app) as client:
        headers = {"Authorization": "Bearer valid-token"}
        assert client.get("/api/v1/organizations/acme/cases", headers=headers).status_code == 200
        assert client.get("/api/v1/organizations/acme/cases", headers=headers).status_code == 200
        assert app.state.oidc_verifier is verifier

    assert len(factory_calls) == 1
    assert verifier.calls == ["valid-token", "valid-token"]
    assert verifier.close_calls == 1


def test_health_endpoints_remain_anonymous(monkeypatch: pytest.MonkeyPatch):
    client = TestClient(_configured_app(monkeypatch))

    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200
    assert client.get("/api/v1/health").status_code == 200


def test_explicit_test_bypass_uses_configured_test_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "true")
    monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)
    monkeypatch.delenv("OIDC_AUDIENCE", raising=False)
    get_settings.cache_clear()

    client = TestClient(create_app())

    response = client.get("/api/v1/organizations/acme/cases")

    assert response.status_code == 200, response.text


@pytest.mark.parametrize("environment", ["development", "staging", "production"])
def test_auth_bypass_is_rejected_outside_test_environment(
    monkeypatch: pytest.MonkeyPatch, environment: str
):
    monkeypatch.setenv("ENVIRONMENT", environment)
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "true")
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="test bypass"):
        create_app()


@pytest.mark.parametrize("environment", ["development", "staging", "production"])
def test_oidc_configuration_is_required_outside_explicit_test_bypass(
    monkeypatch: pytest.MonkeyPatch, environment: str
):
    monkeypatch.setenv("ENVIRONMENT", environment)
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)
    monkeypatch.delenv("OIDC_AUDIENCE", raising=False)
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="OIDC"):
        create_app()

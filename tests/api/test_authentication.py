from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from vulnops.auth.dependencies import principal_from_claims
from vulnops.config import get_settings
from vulnops.main import create_app


class StubVerifier:
    def __init__(self, claims: dict[str, Any] | None = None) -> None:
        self.claims = claims or {
            "iss": "https://issuer.example",
            "aud": "vulnops-api",
            "exp": 4_000_000_000,
            "sub": "user-123",
            "organizations": ["acme"],
            "roles": ["viewer"],
        }
        self.calls: list[str] = []

    def verify_token(self, token: str) -> dict[str, Any]:
        self.calls.append(token)
        if token == "expired-token":
            raise ValueError("expired provider error must not leak")
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

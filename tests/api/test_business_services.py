"""Business-service inventory API and organization RBAC tests."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulnops.services.models  # noqa: F401
from vulnops.config import get_settings
from vulnops.db import Base
from vulnops.main import create_app


class _ClaimsVerifier:
    def __init__(self, roles: list[str]):
        self.roles = roles

    def verify_token(self, token: str) -> dict[str, Any]:
        assert token == "test-token"
        return {
            "sub": "service-test-user",
            "principal_type": "human",
            "organizations": ["org-services"],
            "roles": self.roles,
        }

    def close(self) -> None:
        return None


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()
    app = create_app()
    verifier = _ClaimsVerifier(["admin"])
    app.state.oidc_verifier = verifier

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    from vulnops.api import deps

    app.dependency_overrides[deps.get_db] = override_db
    yield {"client": TestClient(app), "verifier": verifier}
    get_settings.cache_clear()


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-token"}


def test_business_service_create_list_get_and_rbac(env):
    client: TestClient = env["client"]
    response = client.post(
        "/api/v1/organizations/org-services/services",
        json={"name": "Payments", "owner_team": "payments", "criticality": "high"},
        headers=_headers(),
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["organization_id"] == "org-services"
    assert created["name"] == "Payments"
    assert created["owner_team"] == "payments"
    assert created["criticality"] == "high"
    assert created["created_at"]
    assert created["updated_at"]

    listed = client.get("/api/v1/organizations/org-services/services", headers=_headers())
    assert listed.status_code == 200
    assert listed.json() == {"items": [created], "total": 1}

    fetched = client.get(
        f"/api/v1/organizations/org-services/services/{created['id']}",
        headers=_headers(),
    )
    assert fetched.status_code == 200
    assert fetched.json() == created

    env["verifier"].roles = ["viewer"]
    read = client.get("/api/v1/organizations/org-services/services", headers=_headers())
    assert read.status_code == 200
    assert (
        client.get(
            f"/api/v1/organizations/org-services/services/{created['id']}",
            headers=_headers(),
        ).status_code
        == 200
    )

    denied = client.post(
        "/api/v1/organizations/org-services/services",
        json={"name": "Search", "owner_team": "search"},
        headers=_headers(),
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "insufficient_permission"


def test_business_service_owner_role_can_write_via_case_capability(env):
    env["verifier"].roles = ["owner"]
    response = env["client"].post(
        "/api/v1/organizations/org-services/services",
        json={"name": "Search", "owner_team": "search"},
        headers=_headers(),
    )
    assert response.status_code == 201, response.text

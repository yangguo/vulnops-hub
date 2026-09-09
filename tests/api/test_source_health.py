"""Source-health API tests with an isolated in-memory database."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulnops.intelligence.models  # noqa: F401  (register SourceStatus metadata)
from vulnops.config import get_settings
from vulnops.db import Base
from vulnops.intelligence.models import SourceStatus
from vulnops.main import create_app


class _StaticVerifier:
    """Verifier stand-in: always resolves to an admin principal in org-demo."""

    def verify_token(self, token: str) -> dict:
        return {
            "sub": "test-user",
            "principal_type": "human",
            "organizations": ["org-demo"],
            "roles": ["admin"],
        }

    def close(self) -> None:
        return None


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch):
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # share one in-memory DB across connections
    )
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False)

    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()
    from vulnops.api import deps

    app = create_app()

    def _override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[deps.get_db] = _override_db
    app.state.oidc_verifier = _StaticVerifier()
    yield {"client": TestClient(app), "factory": factory}
    get_settings.cache_clear()


def _seed(factory, source: str, freshness: str, minutes_ago: int = 5) -> None:
    session = factory()
    session.add(
        SourceStatus(
            id=f"src_{source}_test",
            source=source,
            scope="global",
            freshness=freshness,
            last_success_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            last_checked_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            last_error=None if freshness == "fresh" else "upstream 500",
        )
    )
    session.commit()
    session.close()


def test_source_health_requires_auth(env):
    resp = env["client"].get("/api/v1/organizations/org-demo/source-health")
    assert resp.status_code == 401


def test_source_health_empty(env):
    resp = env["client"].get(
        "/api/v1/organizations/org-demo/source-health",
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total": 0, "degraded_sources": []}


def test_source_health_lists_rows_and_flags_degraded(env):
    _seed(env["factory"], "defectdojo", "fresh")
    _seed(env["factory"], "wazuh", "stale", minutes_ago=120)
    resp = env["client"].get(
        "/api/v1/organizations/org-demo/source-health",
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["degraded_sources"] == ["wazuh"]
    by_source = {i["source"]: i for i in body["items"]}
    assert by_source["defectdojo"]["freshness"] == "fresh"
    assert by_source["defectdojo"]["last_success_at"] is not None
    assert by_source["wazuh"]["last_error"] == "upstream 500"
    assert by_source["wazuh"]["cursor"] is None

"""CSV/CMDB asset import API tests with an isolated in-memory database."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulnops.assets.models
import vulnops.intelligence.models  # noqa: F401
from vulnops.config import get_settings
from vulnops.db import Base
from vulnops.main import create_app


class _StaticVerifier:
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
        poolclass=StaticPool,
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
    yield {
        "client": TestClient(app),
        "factory": factory,
        "post": lambda csv_text: TestClient(app).post(
            "/api/v1/organizations/org-demo/assets/import",
            content=csv_text,
            headers={"Authorization": "Bearer test-token", "Content-Type": "text/csv"},
        ),
    }
    get_settings.cache_clear()


CSV_SIMPLE = (
    "hostname,name,criticality,environment,owner,internet_exposure\n"
    "web01,Web Frontend,critical,prod,platform,external\n"
    "db01,Database,high,prod,data,internal\n"
)
CSV_UPDATE = "hostname,criticality,owner\nweb01,low,platform-2\n"
CSV_AMBIGUOUS = "hostname,criticality\nweb01,critical\n"


def test_import_requires_auth(env):
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/assets/import",
        content=CSV_SIMPLE,
        headers={"Content-Type": "text/csv"},
    )
    assert resp.status_code == 401


def test_import_creates_assets_with_hostname_alias(env):
    resp = env["post"](CSV_SIMPLE)
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] == 2
    assert resp.json()["skipped"] == 0
    from vulnops.assets.models import Asset, AssetAlias

    session = env["factory"]()
    assets = session.query(Asset).all()
    assert {a.name for a in assets} == {"Web Frontend", "Database"}
    web01 = next(a for a in assets if a.name == "Web Frontend")
    assert web01.criticality == "critical"
    assert web01.internet_exposure == "external"
    aliases = session.query(AssetAlias).filter_by(value="web01").all()
    assert len(aliases) == 1
    assert aliases[0].namespace == "hostname"
    session.close()


def test_reimport_updates_existing_without_duplicates(env):
    env["post"](CSV_SIMPLE)
    resp = env["post"](CSV_UPDATE)
    assert resp.status_code == 200
    assert resp.json()["updated"] == 1
    assert resp.json()["created"] == 0
    from vulnops.assets.models import Asset, AssetAlias

    session = env["factory"]()
    assert session.query(Asset).count() == 2
    assert session.query(AssetAlias).filter_by(value="web01").count() == 1
    web01 = session.query(Asset).filter_by(name="Web Frontend").one()
    assert web01.criticality == "low"
    assert web01.owner == "platform-2"
    session.close()


def test_invalid_rows_skipped_not_fatal(env):
    resp = env["post"]("hostname,criticality\n,low\nbad-host,high\n")
    assert resp.status_code == 200
    body = resp.json()
    assert body["skipped"] == 1
    assert body["created"] == 1


def test_missing_hostname_column_rejected(env):
    resp = env["post"]("name,criticality\nWeb,critical\n")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["skipped_details"][0]["reason"].startswith("missing required 'hostname'")

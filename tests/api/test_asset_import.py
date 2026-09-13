"""CSV/CMDB asset import API tests with an isolated in-memory database."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulnops.assets.models
import vulnops.intelligence.models
import vulnops.matching.models
import vulnops.services.models  # noqa: F401
from vulnops.assets.models import Asset
from vulnops.config import get_settings
from vulnops.db import Base
from vulnops.main import create_app
from vulnops.matching.models import Exposure
from vulnops.services.models import BusinessService


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


def test_import_retains_ip_as_an_observation_alias_without_duplicate_replay(env):
    csv_text = "hostname,ip\nm2-vulnerable-web-01,10.20.30.41\n"

    assert env["post"](csv_text).json()["created"] == 1
    assert env["post"](csv_text).json()["updated"] == 1

    from vulnops.assets.models import AssetAlias

    session = env["factory"]()
    aliases = session.query(AssetAlias).filter_by(value="10.20.30.41").all()
    assert len(aliases) == 1
    assert aliases[0].namespace == "ip"
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

    cleared = env["post"]("hostname,owner\nweb01,\n")
    assert cleared.status_code == 200
    session = env["factory"]()
    assert session.query(Asset).filter_by(name="Web Frontend").one().owner is None
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


def test_import_sets_owner_and_resolves_business_service_id_or_name(env):
    session = env["factory"]()
    session.add_all(
        [
            BusinessService(
                id="svc-payments",
                organization_id="org-demo",
                name="Payments",
                owner_team="payments",
            ),
            BusinessService(
                id="svc-search",
                organization_id="org-demo",
                name="Search",
                owner_team="search",
            ),
        ]
    )
    session.commit()
    session.close()

    response = env["post"](
        "hostname,owner,business_service_id\n"
        "payments-01,payments-oncall,svc-payments\n"
        "search-01,search-oncall,svc-search\n"
    )
    assert response.status_code == 200, response.text
    assert response.json()["created"] == 2

    session = env["factory"]()
    from vulnops.assets.models import Asset

    payments = session.query(Asset).filter_by(name="payments-01").one()
    search = session.query(Asset).filter_by(name="search-01").one()
    assert payments.owner == "payments-oncall"
    assert payments.business_service_id == "svc-payments"
    assert search.owner == "search-oncall"
    assert search.business_service_id == "svc-search"
    session.close()

    by_name = env["post"]("hostname,owner,service\nsearch-name-01,search-oncall,Search\n")
    assert by_name.status_code == 200
    session = env["factory"]()
    search_by_name = session.query(Asset).filter_by(name="search-name-01").one()
    assert search_by_name.business_service_id == "svc-search"
    session.close()

    update = env["post"]("hostname,criticality\npayments-01,low\n")
    assert update.status_code == 200
    session = env["factory"]()
    payments = session.query(Asset).filter_by(name="payments-01").one()
    assert payments.owner == "payments-oncall"
    assert payments.business_service_id == "svc-payments"
    session.close()


def test_ambiguous_business_service_name_is_skipped(env):
    # Simulate legacy rows from before the service-name uniqueness invariant.
    # The current ORM/migration prevents creating these rows normally.
    session = env["factory"]()
    session.execute(text("DROP TABLE business_services"))
    session.execute(
        text(
            """
            CREATE TABLE business_services (
                id VARCHAR(64) NOT NULL PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                name VARCHAR(256) NOT NULL,
                name_normalized VARCHAR(256) NOT NULL,
                owner_team VARCHAR(128) NOT NULL,
                criticality VARCHAR(32),
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
            """
        )
    )
    session.execute(
        text(
            """
            INSERT INTO business_services
                (id, organization_id, name, name_normalized, owner_team, created_at, updated_at)
            VALUES
                ('legacy-svc-a', 'org-demo', 'Payments', 'payments', 'payments-a',
                 '2026-09-10 00:00:00', '2026-09-10 00:00:00'),
                ('legacy-svc-b', 'org-demo', 'payments', 'payments', 'payments-b',
                 '2026-09-10 00:00:00', '2026-09-10 00:00:00')
            """
        )
    )
    session.commit()
    session.close()

    response = env["post"]("hostname,service\nambiguous-01,Payments\n")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["created"] == 0
    assert body["updated"] == 0
    assert body["skipped"] == 1
    assert body["skipped_details"] == [
        {"row": 2, "reason": "ambiguous business service name", "service": "Payments"}
    ]
    session = env["factory"]()
    from vulnops.assets.models import Asset

    assert session.query(Asset).count() == 0
    session.close()


def test_conflicting_exposure_owners_are_bad_request(env):
    session = env["factory"]()
    session.add_all(
        [
            Asset(
                id="asset-api-owner-a",
                organization_id="org-demo",
                name="api-owner-a",
                owner="team-a",
            ),
            Asset(
                id="asset-api-owner-b",
                organization_id="org-demo",
                name="api-owner-b",
                owner="team-b",
            ),
            Exposure(
                id="exp-api-owner-a",
                organization_id="org-demo",
                asset_id="asset-api-owner-a",
                vulnerability_id="CVE-2026-API-A",
                match_class="confirmed",
                confidence=1.0,
                state="active",
            ),
            Exposure(
                id="exp-api-owner-b",
                organization_id="org-demo",
                asset_id="asset-api-owner-b",
                vulnerability_id="CVE-2026-API-B",
                match_class="confirmed",
                confidence=1.0,
                state="active",
            ),
        ]
    )
    session.commit()
    session.close()

    response = env["client"].post(
        "/api/v1/organizations/org-demo/cases",
        json={
            "title": "Conflicting owner case",
            "owner_team": "unassigned",
            "priority": "P1",
            "exposures": ["exp-api-owner-b", "exp-api-owner-a"],
        },
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 400, response.text
    problem = response.json()["detail"]
    assert problem["code"] == "conflicting_exposure_owners"
    assert problem["detail"] == "conflicting exposure owners"

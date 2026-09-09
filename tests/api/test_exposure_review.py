"""Candidate exposure listing and review API tests (isolated in-memory DB)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import vulnops.intelligence.models
import vulnops.matching.models  # noqa: F401  (register Exposure metadata)
from vulnops.config import get_settings
from vulnops.db import Base
from vulnops.db.models.audit_event import AuditEvent
from vulnops.main import create_app
from vulnops.matching.models import Exposure


class _Verifier:
    def __init__(self, roles):
        self.roles = roles

    def verify_token(self, token: str) -> dict:
        return {
            "sub": "reviewer-1" if self.roles == ["owner"] else "user",
            "principal_type": "human",
            "organizations": ["org-demo"],
            "roles": self.roles,
        }

    def close(self) -> None:
        return None


def _candidate(oid: str, state: str = "candidate", vuln: str = "CVE-2026-0001") -> Exposure:
    return Exposure(
        id=f"exp_{oid}",
        organization_id="org-demo",
        vulnerability_id=vuln,
        detection_context="sbom:s1",
        match_class="deterministic",
        confidence=0.4,
        state=state,
    )


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

    def _client_with(roles):
        app.state.oidc_verifier = _Verifier(roles)
        return TestClient(app)

    session = factory()
    session.add(_candidate("cand1"))
    session.add(_candidate("cand2", vuln="CVE-2026-0002"))
    session.add(_candidate("active1", state="active", vuln="CVE-2026-0003"))
    session.commit()
    session.close()
    yield {"app": app, "factory": factory, "client": _client_with(["owner"])}
    get_settings.cache_clear()


AUTH = {"Authorization": "Bearer test-token"}


def test_list_exposures_filters_state(env):
    resp = env["client"].get(
        "/api/v1/organizations/org-demo/exposures?state=candidate", headers=AUTH
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2
    assert {i["id"] for i in body["items"]} == {"exp_cand1", "exp_cand2"}


def test_review_promotes_candidate_to_active(env):
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/exposures/exp_cand1/review",
        json={"decision": "confirmed", "reason": "verified on asset"},
        headers=AUTH,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "active"
    session = env["factory"]()
    audit = session.query(AuditEvent).filter_by(subject_id="exp_cand1").one()
    assert audit.action == "exposure.reviewed"
    assert audit.actor == "reviewer-1"
    session.close()


def test_review_not_affected(env):
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/exposures/exp_cand2/review",
        json={"decision": "not_affected", "reason": "vendor VEX statement"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "not_affected"


def test_review_requires_reason_and_valid_decision(env):
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/exposures/exp_cand1/review",
        json={"decision": "confirmed"},
        headers=AUTH,
    )
    assert resp.status_code == 422
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/exposures/exp_cand1/review",
        json={"decision": "maybe", "reason": "x"},
        headers=AUTH,
    )
    assert resp.status_code == 422


def test_review_rejects_non_candidate(env):
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/exposures/exp_active1/review",
        json={"decision": "confirmed", "reason": "x"},
        headers=AUTH,
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "invalid_state"


def test_review_404_cross_org(env):
    resp = env["client"].post(
        "/api/v1/organizations/other-org/exposures/exp_cand1/review",
        json={"decision": "confirmed", "reason": "x"},
        headers=AUTH,
    )
    assert resp.status_code == 404


def test_review_requires_owner_capability(env):
    # simulate a viewer principal: case:read only, no risk:request
    env["app"].state.oidc_verifier = _Verifier(["viewer"])
    resp = env["client"].post(
        "/api/v1/organizations/org-demo/exposures/exp_cand1/review",
        json={"decision": "confirmed", "reason": "x"},
        headers=AUTH,
    )
    assert resp.status_code == 403

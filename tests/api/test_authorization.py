from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from vulnops.config import get_settings
from vulnops.main import create_app


class ClaimsVerifier:
    """Deterministic verifier used to exercise the authenticated route boundary."""

    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims

    def verify_token(self, token: str) -> dict[str, Any]:
        assert token == "test-token"
        return dict(self.claims)


def _claims(
    *,
    organization_ids: list[str],
    roles: list[str] | None = None,
    scopes: str | list[str] | None = None,
    subject: str = "test-user",
) -> dict[str, Any]:
    return {
        "sub": subject,
        "principal_type": "service" if scopes is not None else "human",
        "organizations": organization_ids,
        "roles": roles or [],
        "scope": scopes or "",
    }


def _client(monkeypatch: pytest.MonkeyPatch, claims: dict[str, Any]) -> TestClient:
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AUTH_TEST_BYPASS_ENABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://issuer.example")
    monkeypatch.setenv("OIDC_AUDIENCE", "vulnops-api")
    get_settings.cache_clear()
    app = create_app()
    app.state.oidc_verifier = ClaimsVerifier(claims)
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-token"}


def _create_case(client: TestClient, organization_id: str) -> dict[str, Any]:
    response = client.post(
        f"/api/v1/organizations/{organization_id}/cases",
        json={"title": "authorization case", "owner_team": "security", "priority": "P2"},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _submit_sbom(client: TestClient, organization_id: str) -> dict[str, Any]:
    response = client.post(
        f"/api/v1/organizations/{organization_id}/sboms",
        json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "authorization-fixture",
                    "version": "1.0.0",
                    "purl": f"pkg:pypi/authorization-fixture@{uuid4().hex}",
                }
            ],
        },
        headers=_headers(),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _problem(response, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    body = response.json()
    assert body["status"] == status
    assert body["code"] == code
    assert body["type"].endswith(f"/problems/{code}")
    assert body["correlation_id"]


def test_viewer_reads_cases_but_cannot_create_or_transition(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_id = f"auth-viewer-{uuid4().hex[:8]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    case = _create_case(admin, organization_id)

    viewer = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["viewer"]))
    read = viewer.get(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}", headers=_headers()
    )
    assert read.status_code == 200, read.text

    create = viewer.post(
        f"/api/v1/organizations/{organization_id}/cases",
        json={"title": "denied", "owner_team": "security"},
        headers=_headers(),
    )
    _problem(create, 403, "insufficient_permission")

    transition = viewer.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/transitions",
        json={"target": "triage"},
        headers=_headers(),
    )
    _problem(transition, 403, "insufficient_permission")


def test_owner_can_create_transition_request_risk_and_submit_verification(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_id = f"auth-owner-{uuid4().hex[:8]}"
    owner = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["owner"]))

    case = _create_case(owner, organization_id)
    transition = owner.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/transitions",
        json={"target": "triage"},
        headers=_headers(),
    )
    assert transition.status_code == 200, transition.text

    risk = owner.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions",
        json={"type": "risk_accepted", "reason": "owner request"},
        headers=_headers(),
    )
    assert risk.status_code == 200, risk.text

    for target in ("assigned", "in_progress", "awaiting_verification"):
        transition = owner.post(
            f"/api/v1/organizations/{organization_id}/cases/{case['id']}/transitions",
            json={"target": target},
            headers=_headers(),
        )
        assert transition.status_code == 200, transition.text

    verification = owner.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/verifications",
        json={"method": "scanner", "coverage": {"status": "partial"}},
        headers=_headers(),
    )
    assert verification.status_code in (200, 422), verification.text


@pytest.mark.parametrize("role", ["owner", "auditor", "risk_approver"])
def test_read_capability_roles_can_read_case_history_and_allowed_transitions(
    monkeypatch: pytest.MonkeyPatch, role: str
):
    organization_id = f"auth-read-{role}-{uuid4().hex[:8]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    case = _create_case(admin, organization_id)
    client = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=[role]))

    endpoints = (
        f"/api/v1/organizations/{organization_id}/cases",
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}",
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/allowed-transitions",
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions",
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/verifications",
    )
    for endpoint in endpoints:
        response = client.get(endpoint, headers=_headers())
        assert response.status_code == 200, f"{role} {endpoint}: {response.text}"


@pytest.mark.parametrize("role", ["viewer", "auditor", "risk_approver"])
def test_non_mutating_roles_cannot_submit_risk_or_verification(
    monkeypatch: pytest.MonkeyPatch, role: str
):
    organization_id = f"auth-write-{role}-{uuid4().hex[:8]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    case = _create_case(admin, organization_id)
    client = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=[role]))

    risk = client.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions",
        json={"type": "risk_accepted", "reason": "not permitted"},
        headers=_headers(),
    )
    _problem(risk, 403, "insufficient_permission")

    verification = client.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/verifications",
        json={"method": "scanner", "coverage": {"status": "partial"}},
        headers=_headers(),
    )
    _problem(verification, 403, "insufficient_permission")


def test_service_scope_is_limited_to_named_sbom_capability(monkeypatch: pytest.MonkeyPatch):
    organization_id = f"auth-service-{uuid4().hex[:8]}"
    service = _client(
        monkeypatch,
        _claims(
            organization_ids=[organization_id],
            scopes="sbom:write",
            subject="ci-service",
        ),
    )
    submitted = _submit_sbom(service, organization_id)

    case_read = service.get(f"/api/v1/organizations/{organization_id}/cases", headers=_headers())
    _problem(case_read, 403, "insufficient_permission")

    sbom_read = service.get(
        f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}", headers=_headers()
    )
    _problem(sbom_read, 403, "insufficient_permission")


def test_service_sbom_read_scope_can_read_metadata(monkeypatch: pytest.MonkeyPatch):
    organization_id = f"auth-service-read-{uuid4().hex[:8]}"
    writer = _client(
        monkeypatch,
        _claims(organization_ids=[organization_id], scopes="sbom:write", subject="ci-writer"),
    )
    submitted = _submit_sbom(writer, organization_id)
    reader = _client(
        monkeypatch,
        _claims(organization_ids=[organization_id], scopes="sbom:read", subject="ci-reader"),
    )

    response = reader.get(
        f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}", headers=_headers()
    )
    assert response.status_code == 200, response.text


def test_sbom_read_requires_sbom_read_and_is_available_to_viewer(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_id = f"auth-sbom-read-{uuid4().hex[:8]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    submitted = _submit_sbom(admin, organization_id)

    viewer = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["viewer"]))
    response = viewer.get(
        f"/api/v1/organizations/{organization_id}/sboms/{submitted['id']}", headers=_headers()
    )
    assert response.status_code == 200, response.text


def test_cross_organization_access_is_not_revealed_even_with_admin(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_a = f"auth-org-a-{uuid4().hex[:8]}"
    organization_b = f"auth-org-b-{uuid4().hex[:8]}"
    admin_a = _client(monkeypatch, _claims(organization_ids=[organization_a], roles=["admin"]))
    case = _create_case(admin_a, organization_a)
    admin_b = _client(monkeypatch, _claims(organization_ids=[organization_b], roles=["admin"]))

    untrusted_org = admin_a.get(f"/api/v1/organizations/{organization_b}/cases", headers=_headers())
    _problem(untrusted_org, 404, "resource_not_found")

    list_response = admin_b.get(f"/api/v1/organizations/{organization_b}/cases", headers=_headers())
    assert list_response.status_code == 200
    assert list_response.json()["items"] == []

    for endpoint in (
        f"/api/v1/organizations/{organization_b}/cases/{case['id']}",
        f"/api/v1/organizations/{organization_b}/cases/{case['id']}/allowed-transitions",
        f"/api/v1/organizations/{organization_b}/cases/{case['id']}/risk-decisions",
        f"/api/v1/organizations/{organization_b}/cases/{case['id']}/verifications",
    ):
        response = admin_b.get(endpoint, headers=_headers())
        _problem(response, 404, "resource_not_found")

    for endpoint, payload in (
        (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/transitions",
            {"target": "triage"},
        ),
        (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/risk-decisions",
            {"type": "risk_accepted", "reason": "cross-org"},
        ),
        (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/verifications",
            {"method": "scanner"},
        ),
    ):
        response = admin_b.post(endpoint, json=payload, headers=_headers())
        _problem(response, 404, "resource_not_found")

    sbom = _submit_sbom(admin_a, organization_a)
    cross_org_sbom = admin_b.get(
        f"/api/v1/organizations/{organization_b}/sboms/{sbom['id']}", headers=_headers()
    )
    _problem(cross_org_sbom, 404, "resource_not_found")


def test_real_wildcard_organization_claim_does_not_grant_global_access(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_id = f"auth-wildcard-{uuid4().hex[:8]}"
    wildcard = _client(monkeypatch, _claims(organization_ids=["*"], roles=["admin"]))
    for path in (
        f"/api/v1/organizations/{organization_id}/cases",
        "/api/v1/organizations/*/cases",
    ):
        response = wildcard.get(path, headers=_headers())
        _problem(response, 404, "resource_not_found")

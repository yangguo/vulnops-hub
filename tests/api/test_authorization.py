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


def _transition_case(client: TestClient, organization_id: str, case_id: str, target: str) -> None:
    response = client.post(
        f"/api/v1/organizations/{organization_id}/cases/{case_id}/transitions",
        json={"target": target},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text


def _prepare_case_for_route(
    client: TestClient, organization_id: str, route_name: str
) -> dict[str, Any]:
    case = _create_case(client, organization_id)
    if route_name == "risk_request":
        _transition_case(client, organization_id, case["id"], "triage")
    elif route_name == "verification_submit":
        for target in ("triage", "assigned", "in_progress", "awaiting_verification"):
            _transition_case(client, organization_id, case["id"], target)
    return case


def _route_request(
    client: TestClient,
    organization_id: str,
    route_name: str,
    case: dict[str, Any] | None,
    sbom: dict[str, Any] | None,
):
    case_id = case["id"] if case else "case_missing"
    if route_name == "case_create":
        return client.post(
            f"/api/v1/organizations/{organization_id}/cases",
            json={"title": "matrix case", "owner_team": "security", "priority": "P2"},
            headers=_headers(),
        )
    if route_name == "case_list":
        return client.get(f"/api/v1/organizations/{organization_id}/cases", headers=_headers())
    if route_name == "case_detail":
        return client.get(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}", headers=_headers()
        )
    if route_name == "allowed_transitions":
        return client.get(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}/allowed-transitions",
            headers=_headers(),
        )
    if route_name == "case_transition":
        return client.post(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}/transitions",
            json={"target": "triage"},
            headers=_headers(),
        )
    if route_name == "risk_request":
        return client.post(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}/risk-decisions",
            json={"type": "risk_accepted", "reason": "matrix request"},
            headers=_headers(),
        )
    if route_name == "risk_history":
        return client.get(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}/risk-decisions",
            headers=_headers(),
        )
    if route_name == "verification_history":
        return client.get(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}/verifications",
            headers=_headers(),
        )
    if route_name == "verification_submit":
        return client.post(
            f"/api/v1/organizations/{organization_id}/cases/{case_id}/verifications",
            json={"method": "scanner", "coverage": {"status": "partial"}},
            headers=_headers(),
        )
    if route_name == "sbom_submit":
        return client.post(
            f"/api/v1/organizations/{organization_id}/sboms",
            json={
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "matrix-fixture",
                        "version": "1.0.0",
                        "purl": f"pkg:pypi/matrix-fixture@{uuid4().hex}",
                    }
                ],
            },
            headers=_headers(),
        )
    if route_name == "sbom_detail":
        return client.get(
            f"/api/v1/organizations/{organization_id}/sboms/{sbom['id']}",
            headers=_headers(),
        )
    raise AssertionError(f"unknown route matrix entry: {route_name}")


ROUTE_EXPECTED_STATUS = {
    "case_create": {
        "viewer": 403,
        "owner": 200,
        "auditor": 403,
        "risk_approver": 403,
        "service": 403,
        "cross_org": 404,
    },
    "case_list": {
        "viewer": 200,
        "owner": 200,
        "auditor": 200,
        "risk_approver": 200,
        "service": 403,
        "cross_org": 404,
    },
    "case_detail": {
        "viewer": 200,
        "owner": 200,
        "auditor": 200,
        "risk_approver": 200,
        "service": 403,
        "cross_org": 404,
    },
    "allowed_transitions": {
        "viewer": 200,
        "owner": 200,
        "auditor": 200,
        "risk_approver": 200,
        "service": 403,
        "cross_org": 404,
    },
    "case_transition": {
        "viewer": 403,
        "owner": 200,
        "auditor": 403,
        "risk_approver": 403,
        "service": 403,
        "cross_org": 404,
    },
    "risk_request": {
        "viewer": 403,
        "owner": 200,
        "auditor": 403,
        "risk_approver": 403,
        "service": 403,
        "cross_org": 404,
    },
    "risk_history": {
        "viewer": 200,
        "owner": 200,
        "auditor": 200,
        "risk_approver": 200,
        "service": 403,
        "cross_org": 404,
    },
    "verification_history": {
        "viewer": 200,
        "owner": 200,
        "auditor": 200,
        "risk_approver": 200,
        "service": 403,
        "cross_org": 404,
    },
    "verification_submit": {
        "viewer": 403,
        "owner": 200,
        "auditor": 403,
        "risk_approver": 403,
        "service": 403,
        "cross_org": 404,
    },
    "sbom_submit": {
        "viewer": 403,
        "owner": 403,
        "auditor": 403,
        "risk_approver": 403,
        "service": 201,
        "cross_org": 404,
    },
    "sbom_detail": {
        "viewer": 200,
        "owner": 200,
        "auditor": 403,
        "risk_approver": 200,
        "service": 200,
        "cross_org": 404,
    },
}


PRINCIPAL_NAMES = ("viewer", "owner", "auditor", "risk_approver", "service", "cross_org")


def _claims_for_matrix(
    principal_name: str, organization_id: str, outside_organization_id: str
) -> dict[str, Any]:
    if principal_name == "viewer":
        return _claims(organization_ids=[organization_id], roles=["viewer"])
    if principal_name == "owner":
        return _claims(organization_ids=[organization_id], roles=["owner"])
    if principal_name == "auditor":
        return _claims(organization_ids=[organization_id], roles=["auditor"])
    if principal_name == "risk_approver":
        return _claims(organization_ids=[organization_id], roles=["risk_approver"])
    if principal_name == "service":
        return _claims(
            organization_ids=[organization_id],
            scopes=["sbom:read", "sbom:write"],
            subject="matrix-ci",
        )
    if principal_name == "cross_org":
        return _claims(
            organization_ids=[outside_organization_id], roles=["admin"], subject="cross-org-admin"
        )
    raise AssertionError(f"unknown principal matrix entry: {principal_name}")


@pytest.mark.parametrize("route_name", tuple(ROUTE_EXPECTED_STATUS))
@pytest.mark.parametrize("principal_name", PRINCIPAL_NAMES)
def test_all_business_routes_have_literal_principal_status_matrix(
    monkeypatch: pytest.MonkeyPatch, route_name: str, principal_name: str
):
    organization_id = f"matrix-{route_name}-{principal_name}-{uuid4().hex[:8]}"
    outside_organization_id = f"outside-{uuid4().hex[:8]}"
    admin = _client(monkeypatch, _claims(organization_ids=[organization_id], roles=["admin"]))
    case = None
    sbom = None
    if route_name in {
        "case_detail",
        "allowed_transitions",
        "case_transition",
        "risk_request",
        "risk_history",
        "verification_history",
        "verification_submit",
    }:
        case = _prepare_case_for_route(admin, organization_id, route_name)
    if route_name == "sbom_detail":
        sbom = _submit_sbom(admin, organization_id)

    client = _client(
        monkeypatch,
        _claims_for_matrix(principal_name, organization_id, outside_organization_id),
    )
    response = _route_request(client, organization_id, route_name, case, sbom)
    expected = ROUTE_EXPECTED_STATUS[route_name][principal_name]
    assert response.status_code == expected, (
        f"route={route_name} principal={principal_name} "
        f"expected={expected} actual={response.status_code}: {response.text}"
    )


@pytest.mark.parametrize(
    ("route_name", "method", "payload"),
    [
        ("case_detail", "get", None),
        ("allowed_transitions", "get", None),
        ("case_transition", "post", b"not-json"),
        ("risk_request", "post", b"not-json"),
        ("risk_history", "get", None),
        ("verification_history", "get", None),
        ("verification_submit", "post", b"not-json"),
    ],
)
def test_cross_org_resource_is_hidden_before_capability_and_validation(
    monkeypatch: pytest.MonkeyPatch, route_name: str, method: str, payload: bytes | None
):
    organization_a = f"ordering-a-{uuid4().hex[:8]}"
    organization_b = f"ordering-b-{uuid4().hex[:8]}"
    admin_a = _client(monkeypatch, _claims(organization_ids=[organization_a], roles=["admin"]))
    case = _prepare_case_for_route(admin_a, organization_a, route_name)
    client_b = _client(
        monkeypatch,
        _claims(organization_ids=[organization_b], roles=["service"], scopes="sbom:write"),
    )
    path = {
        "case_detail": f"/api/v1/organizations/{organization_b}/cases/{case['id']}",
        "allowed_transitions": (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/allowed-transitions"
        ),
        "case_transition": (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/transitions"
        ),
        "risk_request": (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/risk-decisions"
        ),
        "risk_history": (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/risk-decisions"
        ),
        "verification_history": (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/verifications"
        ),
        "verification_submit": (
            f"/api/v1/organizations/{organization_b}/cases/{case['id']}/verifications"
        ),
    }[route_name]
    if method == "get":
        response = client_b.get(path, headers=_headers())
    else:
        response = client_b.post(path, content=payload, headers=_headers())
    _problem(response, 404, "resource_not_found")


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


def test_risk_approver_approves_another_principal_request(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_id = f"auth-approval-{uuid4().hex[:8]}"
    requester = _client(
        monkeypatch,
        _claims(organization_ids=[organization_id], roles=["owner"], subject="requester"),
    )
    case = _create_case(requester, organization_id)
    _transition_case(requester, organization_id, case["id"], "triage")
    requested = requester.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions",
        json={"type": "risk_accepted", "reason": "maintenance window"},
        headers=_headers(),
    )
    assert requested.status_code == 200, requested.text
    decision_id = requested.json()["id"]
    assert requested.json()["status"] == "pending_approval"
    assert requested.json()["case_status"] == "triage"

    approver = _client(
        monkeypatch,
        _claims(
            organization_ids=[organization_id],
            roles=["risk_approver"],
            subject="approver",
        ),
    )
    approved = approver.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions/{decision_id}/approval",
        json={"outcome": "approve", "reason": "independent review"},
        headers=_headers(),
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["approver"] == "approver"
    assert approved.json()["approver_role"] == "risk_approver"
    assert approved.json()["case_status"] == "risk_accepted"


def test_service_principal_cannot_use_risk_approval_endpoint(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_id = f"auth-service-approval-{uuid4().hex[:8]}"
    requester = _client(
        monkeypatch,
        _claims(organization_ids=[organization_id], roles=["owner"], subject="requester"),
    )
    case = _create_case(requester, organization_id)
    _transition_case(requester, organization_id, case["id"], "triage")
    requested = requester.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions",
        json={"type": "risk_accepted", "reason": "maintenance window"},
        headers=_headers(),
    )
    assert requested.status_code == 200, requested.text

    service = _client(
        monkeypatch,
        _claims(
            organization_ids=[organization_id],
            scopes="sbom:write",
            subject="ci-service",
        ),
    )
    response = service.post(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}/risk-decisions/{requested.json()['id']}/approval",
        json={"outcome": "approve", "reason": "service must not approve"},
        headers=_headers(),
    )
    _problem(response, 403, "insufficient_permission")


def test_cross_org_risk_approval_is_hidden_before_capability_and_body_validation(
    monkeypatch: pytest.MonkeyPatch,
):
    organization_a = f"auth-approval-a-{uuid4().hex[:8]}"
    organization_b = f"auth-approval-b-{uuid4().hex[:8]}"
    requester = _client(
        monkeypatch,
        _claims(organization_ids=[organization_a], roles=["owner"], subject="requester"),
    )
    case = _create_case(requester, organization_a)
    _transition_case(requester, organization_a, case["id"], "triage")
    requested = requester.post(
        f"/api/v1/organizations/{organization_a}/cases/{case['id']}/risk-decisions",
        json={"type": "risk_accepted", "reason": "maintenance window"},
        headers=_headers(),
    )
    assert requested.status_code == 200, requested.text

    cross_org = _client(
        monkeypatch,
        _claims(organization_ids=[organization_b], scopes="sbom:write", subject="ci-service"),
    )
    response = cross_org.post(
        f"/api/v1/organizations/{organization_b}/cases/{case['id']}/risk-decisions/{requested.json()['id']}/approval",
        json={"actor": "spoof", "outcome": "approve"},
        headers=_headers(),
    )
    _problem(response, 404, "resource_not_found")

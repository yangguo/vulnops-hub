import pytest
from fastapi.testclient import TestClient

from vulnops.main import create_app


def test_case_transition_api_flow():
    app = create_app()
    client = TestClient(app)

    # Create case
    resp = client.post(
        "/api/v1/organizations/acme/cases",
        json={
            "title": "Fix CVE-2026-12345",
            "owner_team": "secops",
            "priority": "P1",
            "exposures": ["exp_01"],
        },
    )
    assert resp.status_code in (200, 201)
    case_id = resp.json()["id"]

    # Get allowed transitions for new case
    resp = client.get(f"/api/v1/organizations/acme/cases/{case_id}/allowed-transitions")
    assert resp.status_code == 200
    assert "triage" in resp.json()["allowed"]

    # Transition to triage
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "triage", "reason": "triage"},
        headers={"Idempotency-Key": "key-1"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "triage"

    # If-Match concurrency: stale version should fail
    # Get current version
    case = client.get(f"/api/v1/organizations/acme/cases/{case_id}").json()
    etag = case.get("version") or case.get("etag") or "1"
    # Try with stale etag
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "assigned", "reason": "assign"},
        headers={"If-Match": '"wrong-etag"', "Idempotency-Key": "key-2"},
    )
    # Should be 412 or 409
    assert resp.status_code in (409, 412, 422)

    # Correct transition with proper If-Match
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "assigned", "reason": "assign"},
        headers={"If-Match": f'"{etag}"', "Idempotency-Key": "key-3"},
    )
    assert resp.status_code == 200

    # Verify requires coverage
    # Move to in_progress and awaiting_verification first
    for target in ["in_progress", "awaiting_verification"]:
        client.post(
            f"/api/v1/organizations/acme/cases/{case_id}/transitions",
            json={"target": target, "reason": target},
        )

    # Try verification with incomplete coverage - should fail to close
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/verifications",
        json={
            "method": "scanner",
            "asserted_result": "remediated",
            "evidence_ids": ["ev_scan"],
            "coverage": {"status": "partial"},
        },
    )
    assert resp.status_code in (200, 422)
    if resp.status_code == 200:
        assert resp.json()["status"] != "closed"


def test_risk_decision_api_requires_approval():
    app = create_app()
    client = TestClient(app)

    resp = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "Risk accept test", "owner_team": "t1", "priority": "P2"},
    )
    case_id = resp.json()["id"]
    client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "triage", "reason": "triage"},
    )

    # Create risk acceptance without approver should be pending
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions",
        json={
            "type": "risk_accepted",
            "scope": {"exposure_ids": ["exp_01"]},
            "reason": "need window",
            "compensating_controls": ["WAF"],
            "expires_at": "2026-10-05T00:00:00Z",
            "evidence_ids": ["ev1"],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "pending_approval"
    assert resp.json()["case_status"] == "triage"

    listed = client.get(f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions")
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"][0]["requested_by"] == "test-principal"
    assert listed.json()["items"][0]["approver"] is None


@pytest.mark.parametrize(
    "identity_field",
    [
        "actor",
        "requested_by",
        "requestedBy",
        "requester",
        "approver",
        "approved_by",
        "approvedBy",
        "approver_role",
        "approverRole",
    ],
)
def test_workflow_identity_fields_are_rejected_in_request_json(identity_field: str):
    app = create_app()
    client = TestClient(app)

    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "spoof test", "owner_team": "t1", "priority": "P2"},
    )
    assert case_response.status_code == 200, case_response.text
    case_id = case_response.json()["id"]

    if identity_field == "actor":
        response = client.post(
            f"/api/v1/organizations/acme/cases/{case_id}/transitions",
            json={"target": "triage", identity_field: "attacker"},
        )
    else:
        transition = client.post(
            f"/api/v1/organizations/acme/cases/{case_id}/transitions",
            json={"target": "triage"},
        )
        assert transition.status_code == 200, transition.text
        response = client.post(
            f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions",
            json={
                "type": "risk_accepted",
                "reason": "spoof test",
                identity_field: "attacker",
            },
        )

    assert response.status_code == 422, response.text
    current = client.get(f"/api/v1/organizations/acme/cases/{case_id}")
    assert current.status_code == 200, current.text
    assert current.json()["status"] == ("new" if identity_field == "actor" else "triage")


def test_risk_approval_is_separate_and_self_approval_is_rejected():
    app = create_app()
    client = TestClient(app)

    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "approval test", "owner_team": "t1", "priority": "P2"},
    )
    assert case_response.status_code == 200, case_response.text
    case_id = case_response.json()["id"]
    transition = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "triage"},
    )
    assert transition.status_code == 200, transition.text

    request_response = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions",
        json={"type": "risk_accepted", "reason": "approval test"},
    )
    assert request_response.status_code == 200, request_response.text
    decision_id = request_response.json()["id"]

    approval_response = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions/{decision_id}/approval",
        json={"outcome": "approve", "reason": "same principal"},
    )
    assert approval_response.status_code == 422, approval_response.text

    current = client.get(f"/api/v1/organizations/acme/cases/{case_id}")
    assert current.json()["status"] == "triage"


def test_verification_actor_identity_field_is_rejected():
    app = create_app()
    client = TestClient(app)
    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "verification actor test", "owner_team": "t1", "priority": "P2"},
    )
    assert case_response.status_code == 200, case_response.text
    case_id = case_response.json()["id"]
    for target in ("triage", "assigned", "in_progress", "awaiting_verification"):
        transition = client.post(
            f"/api/v1/organizations/acme/cases/{case_id}/transitions",
            json={"target": target},
        )
        assert transition.status_code == 200, transition.text

    response = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/verifications",
        json={"method": "scanner", "actor": "attacker", "coverage": {"status": "partial"}},
    )
    assert response.status_code == 422, response.text

import pytest
from fastapi.testclient import TestClient
from vulnops.main import create_app


def test_case_transition_api_flow():
    app = create_app()
    client = TestClient(app)

    # Create case
    resp = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "Fix CVE-2026-12345", "owner_team": "secops", "priority": "P1", "exposures": ["exp_01"]},
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
        json={"target": "triage", "reason": "triage", "actor": "analyst"},
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
        json={"target": "assigned", "reason": "assign", "actor": "manager"},
        headers={"If-Match": '"wrong-etag"', "Idempotency-Key": "key-2"},
    )
    # Should be 412 or 409
    assert resp.status_code in (409, 412, 422)

    # Correct transition with proper If-Match
    resp = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "assigned", "reason": "assign", "actor": "manager"},
        headers={"If-Match": f'"{etag}"', "Idempotency-Key": "key-3"},
    )
    assert resp.status_code == 200

    # Verify requires coverage
    # Move to in_progress and awaiting_verification first
    for target in ["in_progress", "awaiting_verification"]:
        client.post(
            f"/api/v1/organizations/acme/cases/{case_id}/transitions",
            json={"target": target, "reason": target, "actor": "a"},
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
    client.post(f"/api/v1/organizations/acme/cases/{case_id}/transitions", json={"target": "triage", "reason": "triage", "actor": "analyst"})

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
            "requested_by": "user1",
        },
    )
    assert resp.status_code in (200, 201, 202)
    assert resp.json().get("status") in ("pending_approval", "approval_required", "pending", "requires_approval")

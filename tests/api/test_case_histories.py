from uuid import uuid4

from fastapi.testclient import TestClient

from vulnops.main import create_app


def _create_case(client, org, title, priority="P2"):
    resp = client.post(
        f"/api/v1/organizations/{org}/cases",
        json={"title": title, "priority": priority, "owner_team": "platform"},
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()


def test_list_risk_decisions_returns_history():
    client = TestClient(create_app())
    org = f"rd-org-{uuid4().hex[:8]}"
    case = _create_case(client, org, "accept this")
    cid = case["id"]
    client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/transitions",
        json={"target": "triage"},
    )
    resp = client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/risk-decisions",
        json={
            "type": "risk_accepted",
            "reason": "waiver until Q4",
            "evidence_ids": ["e1"],
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )
    assert resp.status_code in (200, 201), resp.text

    resp = client.get(f"/api/v1/organizations/{org}/cases/{cid}/risk-decisions")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["type"] == "risk_accepted"
    assert items[0]["status"] == "pending_approval"
    assert items[0]["case_id"] == cid
    assert items[0]["requested_by"] == "test-principal"
    assert items[0]["approver"] is None
    assert items[0]["created_at"]


def test_list_risk_decisions_unknown_case_404():
    client = TestClient(create_app())
    resp = client.get("/api/v1/organizations/rd-org/cases/case_nope/risk-decisions")
    assert resp.status_code == 404


def test_list_risk_decisions_cross_org_404():
    client = TestClient(create_app())
    org_a = f"rd-org-a-{uuid4().hex[:8]}"
    org_b = f"rd-org-b-{uuid4().hex[:8]}"
    case = _create_case(client, org_a, "mine")
    resp = client.get(f"/api/v1/organizations/{org_b}/cases/{case['id']}/risk-decisions")
    assert resp.status_code == 404


def test_list_verifications_returns_history():
    client = TestClient(create_app())
    org = f"ver-org-{uuid4().hex[:8]}"
    case = _create_case(client, org, "prove it")
    cid = case["id"]
    for target in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        client.post(
            f"/api/v1/organizations/{org}/cases/{cid}/transitions",
            json={"target": target},
        )
    resp = client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/verifications",
        json={
            "method": "scanner",
            "evidence_ids": ["ev1"],
            "coverage": {"status": "complete", "scope_version": "v2"},
        },
    )
    assert resp.status_code in (200, 201), resp.text

    resp = client.get(f"/api/v1/organizations/{org}/cases/{cid}/verifications")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["method"] == "scanner"
    assert items[0]["status"] == "closed"
    assert items[0]["coverage"] == {"status": "complete", "scope_version": "v2"}
    assert items[0]["created_at"]


def test_list_verifications_unknown_case_404():
    client = TestClient(create_app())
    resp = client.get("/api/v1/organizations/ver-org/cases/case_nope/verifications")
    assert resp.status_code == 404

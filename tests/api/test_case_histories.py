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
        json={"target": "triage", "actor": "t"},
    )
    resp = client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/risk-decisions",
        json={
            "type": "risk_accepted",
            "reason": "waiver until Q4",
            "evidence_ids": ["e1"],
            "requested_by": "alice",
            "approver": "bob",
            "approver_role": "security_lead",
        },
    )
    assert resp.status_code in (200, 201), resp.text

    resp = client.get(f"/api/v1/organizations/{org}/cases/{cid}/risk-decisions")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["type"] == "risk_accepted"
    assert items[0]["status"] == "approved"
    assert items[0]["case_id"] == cid
    assert items[0]["approver"] == "bob"
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

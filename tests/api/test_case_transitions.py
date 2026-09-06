from datetime import UTC, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm.attributes import set_committed_value

from vulnops.auth.models import Principal
from vulnops.cases.models import RiskDecision
from vulnops.cases.service import CaseService
from vulnops.db import get_engine, get_sessionmaker
from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.outbox_event import OutboxEvent
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


def test_case_transition_api_preserves_request_and_correlation_trace():
    app = create_app()
    client = TestClient(app)
    response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "trace test", "owner_team": "secops", "priority": "P2"},
    )
    assert response.status_code == 200, response.text
    case_id = response.json()["id"]
    response = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "triage"},
        headers={"X-Request-ID": "req-api-transition", "X-Correlation-ID": "corr-api-transition"},
    )
    assert response.status_code == 200, response.text

    session = get_sessionmaker(get_engine())()
    try:
        audit = session.scalar(
            select(AuditEvent).where(AuditEvent.correlation_id == "corr-api-transition")
        )
        outbox = session.scalar(
            select(OutboxEvent).where(OutboxEvent.correlation_id == "corr-api-transition")
        )
        assert audit is not None
        assert audit.request_id == "req-api-transition"
        assert audit.actor_principal_type == "human"
        assert outbox is not None
        assert outbox.payload["request_id"] == "req-api-transition"
        assert outbox.payload["correlation_id"] == "corr-api-transition"
    finally:
        session.close()


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
    ("field", "value", "detail"),
    [
        ("type", "unsupported", "unsupported risk decision type"),
        ("reason", "   ", "risk decision reason is required"),
        ("reason", None, "risk decision reason is required"),
        ("evidence_ids", [], "risk decision evidence_ids must contain at least one item"),
        ("evidence_ids", [""], "risk decision evidence_ids must contain only nonblank strings"),
        ("expires_at", "not-a-timestamp", "risk decision expires_at must be an ISO-8601 timestamp"),
        ("expires_at", "2020-01-01T00:00:00", "risk decision expires_at must be timezone-aware"),
        ("expires_at", None, "risk decision expires_at is required"),
    ],
)
def test_risk_decision_api_returns_stable_problem_details_for_invalid_request(
    field: str, value: object, detail: str
):
    app = create_app()
    client = TestClient(app)
    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "validation test", "owner_team": "t1", "priority": "P2"},
    )
    assert case_response.status_code == 200, case_response.text
    case_id = case_response.json()["id"]
    transition = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/transitions",
        json={"target": "triage"},
    )
    assert transition.status_code == 200, transition.text

    payload = {
        "type": "risk_accepted",
        "reason": "valid reason",
        "evidence_ids": ["ev1"],
        "expires_at": "2099-01-01T00:00:00Z",
    }
    payload[field] = value
    response = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions",
        json=payload,
    )
    assert response.status_code == 422, response.text
    body = response.json()["detail"]
    assert body["code"] == "invalid_risk_decision"
    assert body["status"] == 422
    assert body["detail"] == detail


def test_risk_approval_api_rejects_expired_decision_with_stable_problem_details():
    app = create_app()
    client = TestClient(app)
    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "expired approval", "owner_team": "t1", "priority": "P2"},
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
        json={
            "type": "risk_accepted",
            "reason": "temporary exception",
            "evidence_ids": ["ev-expired"],
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )
    assert request_response.status_code == 200, request_response.text
    decision_id = request_response.json()["id"]

    session = get_sessionmaker(get_engine())()
    try:
        decision = session.get(RiskDecision, decision_id)
        assert decision is not None
        decision.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    finally:
        session.close()

    app.state.test_principal = Principal(
        subject="approver",
        principal_type="human",
        organization_ids={"acme"},
        roles={"risk_approver"},
    )

    approval = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions/{decision_id}/approval",
        json={"outcome": "approve", "reason": "late review"},
    )
    assert approval.status_code == 422, approval.text
    body = approval.json()["detail"]
    assert body["code"] == "invalid_risk_approval"
    assert body["status"] == 422
    assert body["detail"] == "risk decision expires_at must be in the future"
    current = client.get(f"/api/v1/organizations/acme/cases/{case_id}")
    assert current.json()["status"] == "triage"


def test_risk_decision_api_canonicalizes_aware_non_utc_orm_expiry_response(monkeypatch):
    app = create_app()
    client = TestClient(app)
    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "canonical response", "owner_team": "t1", "priority": "P2"},
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
        json={
            "type": "risk_accepted",
            "reason": "temporary exception",
            "evidence_ids": ["ev-canonical"],
            "expires_at": "2030-01-01T10:00:00Z",
        },
    )
    assert request_response.status_code == 200, request_response.text

    original_list = CaseService.list_risk_decisions

    def list_with_non_utc_orm_value(self, case_id):
        decisions = original_list(self, case_id)
        for decision in decisions:
            set_committed_value(
                decision,
                "expires_at",
                datetime(2030, 1, 1, 18, 0, tzinfo=timezone(timedelta(hours=8))),
            )
        return [self.get_risk_decision(decision.id) for decision in decisions]

    monkeypatch.setattr(CaseService, "list_risk_decisions", list_with_non_utc_orm_value)
    response = client.get(f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions")
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["expires_at"] == "2030-01-01T10:00:00+00:00"


def test_risk_approval_api_maps_malformed_orm_expiry_to_stable_problem_details(monkeypatch):
    app = create_app()
    client = TestClient(app)
    case_response = client.post(
        "/api/v1/organizations/acme/cases",
        json={"title": "malformed approval", "owner_team": "t1", "priority": "P2"},
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
        json={
            "type": "risk_accepted",
            "reason": "temporary exception",
            "evidence_ids": ["ev-malformed"],
            "expires_at": "2030-01-01T10:00:00Z",
        },
    )
    assert request_response.status_code == 200, request_response.text
    decision_id = request_response.json()["id"]

    original_get = CaseService.get_risk_decision

    def get_with_malformed_orm_value(self, loaded_decision_id):
        decision = original_get(self, loaded_decision_id)
        set_committed_value(decision, "expires_at", "not-a-datetime")
        return decision

    monkeypatch.setattr(CaseService, "get_risk_decision", get_with_malformed_orm_value)
    app.state.test_principal = Principal(
        subject="approver",
        principal_type="human",
        organization_ids={"acme"},
        roles={"risk_approver"},
    )
    approval = client.post(
        f"/api/v1/organizations/acme/cases/{case_id}/risk-decisions/{decision_id}/approval",
        json={"outcome": "approve", "reason": "review malformed expiry"},
    )
    assert approval.status_code == 422, approval.text
    body = approval.json()["detail"]
    assert body["code"] == "invalid_risk_approval"
    assert body["status"] == 422
    assert body["detail"] == "risk decision expires_at must be timezone-aware"
    current = client.get(f"/api/v1/organizations/acme/cases/{case_id}")
    assert current.status_code == 200, current.text
    assert current.json()["status"] == "triage"


@pytest.mark.parametrize(
    "identity_field",
    [
        "actor",
        "actor_id",
        "actorId",
        "actor_role",
        "actorRole",
        "requested_by",
        "requestedBy",
        "requester",
        "requested_by_id",
        "requested_by_role",
        "requestedByRole",
        "requester_id",
        "requesterId",
        "requester_role",
        "requesterRole",
        "approver",
        "approver_id",
        "approved_by",
        "approvedBy",
        "approved_by_id",
        "approvedById",
        "approver_role",
        "approverRole",
        "approved_by_role",
        "approvedByRole",
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
                "expires_at": "2099-01-01T00:00:00Z",
                "evidence_ids": ["ev1"],
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
        json={
            "type": "risk_accepted",
            "reason": "approval test",
            "expires_at": "2099-01-01T00:00:00Z",
            "evidence_ids": ["ev1"],
        },
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

from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.cases.service import CaseService


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.cases.models  # noqa
    Base.metadata.create_all(bind=eng)
    return eng


def test_expired_acceptance_reopens_case():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    # Risk acceptance requires approval and expiry
    decision = svc.create_risk_decision(
        case.id,
        type="risk_accepted",
        reason="Vendor patch requires window",
        compensating_controls=["WAF rule 314"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        evidence_ids=["ev_change_459"],
        requested_by="user1",
        approver="risk_approver",
        actor="requester",
    )
    assert decision.status == "approved"
    assert svc.get_case(case.id).status == "risk_accepted"

    # Advance clock 31 days and process expirations
    future = datetime.now(timezone.utc) + timedelta(days=31)
    count = svc.process_expirations(now=future)
    assert count >= 1
    assert svc.get_case(case.id).status == "triage"
    session.close()


def test_risk_acceptance_requires_approval():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")

    # Try without approver - should be pending or require approval
    decision = svc.create_risk_decision(
        case.id,
        type="risk_accepted",
        reason="need window",
        expires_at=datetime.now(timezone.utc) + timedelta(days=10),
        evidence_ids=["ev1"],
        requested_by="user1",
        actor="user1",
        # no approver
    )
    # Should be pending approval, not approved
    assert decision.status in ("pending_approval", "approval_required", "pending")
    # Case should not be risk_accepted until approved
    assert svc.get_case(case.id).status != "risk_accepted"
    session.close()


def test_revoked_decision_does_not_auto_close():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = svc.create_risk_decision(
        case.id,
        type="risk_accepted",
        reason="temp",
        expires_at=datetime.now(timezone.utc) + timedelta(days=10),
        evidence_ids=["ev1"],
        requested_by="u1",
        approver="approver",
        actor="a",
    )
    assert svc.get_case(case.id).status == "risk_accepted"
    # Revoke via new event - should go back to triage, not closed
    svc.revoke_decision(decision.id, actor="approver", reason="revoked")
    assert svc.get_case(case.id).status == "triage"
    session.close()

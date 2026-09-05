import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.cases.models import RemediationCase, CaseStatus
from vulnops.cases.service import CaseService


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.cases.models  # noqa
    import vulnops.db.models.audit_event  # noqa
    import vulnops.db.models.outbox_event  # noqa
    Base.metadata.create_all(bind=eng)
    return eng


def _svc():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    return CaseService(session), session


def test_case_lifecycle_new_to_closed():
    svc, session = _svc()
    case = svc.create_case(
        organization_id="org1",
        title="Fix CVE-2026-12345 on payments-api",
        owner_team="secops",
        priority="P1",
        exposures=["exp_01"],
    )
    assert case.status == "new"

    svc.transition(case.id, "triage", actor="analyst")
    assert svc.get_case(case.id).status == "triage"

    svc.transition(case.id, "assigned", actor="manager", extra={"assignee": "alice"})
    assert svc.get_case(case.id).status == "assigned"

    svc.transition(case.id, "in_progress", actor="alice")
    assert svc.get_case(case.id).status == "in_progress"

    svc.transition(case.id, "awaiting_verification", actor="alice")
    assert svc.get_case(case.id).status == "awaiting_verification"

    # Need positive verification to close
    result = svc.verify(
        case.id,
        method="wazuh_inventory",
        evidence_ids=["ev_wazuh_1"],
        coverage={"status": "complete", "scope_version": "inventory-policy-3"},
        actor="verifier",
    )
    assert result.status == "closed"
    assert svc.get_case(case.id).status == "closed"
    session.close()


def test_invalid_transition_raises():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P2")
    # Cannot go new -> closed directly
    with pytest.raises(ValueError, match="not allowed"):
        svc.transition(case.id, "closed", actor="alice")
    session.close()


def test_concurrent_update_with_stale_version_fails():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P2")
    # Simulate version check via updated_at / version field
    # First transition bumps version
    initial_version = case.version
    svc.transition(case.id, "triage", actor="a1", expected_version=initial_version)
    fresh = svc.get_case(case.id)
    # Stale version should fail (use initial_version which is now stale)
    with pytest.raises(ValueError, match="conflict"):
        svc.transition(case.id, "assigned", actor="a2", expected_version=initial_version)  # stale
    # Correct version succeeds
    svc.transition(case.id, "assigned", actor="a2", expected_version=fresh.version)
    assert svc.get_case(case.id).status == "assigned"
    session.close()


def test_new_confirmed_evidence_reopens_closed_case():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1", exposures=["exp_1"])
    for s in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        svc.transition(case.id, s, actor="a")
    svc.verify(case.id, method="wazuh_inventory", evidence_ids=["ev1"], coverage={"status": "complete"}, actor="verifier")
    assert svc.get_case(case.id).status == "closed"

    # New confirming evidence should reopen
    svc.reopen_on_evidence(case.id, evidence_id="ev_new_confirm", reason="new scanner confirmed detection")
    assert svc.get_case(case.id).status == "reopened"
    # Reopened should go back to triage
    svc.transition(case.id, "triage", actor="analyst")
    assert svc.get_case(case.id).status == "triage"
    session.close()

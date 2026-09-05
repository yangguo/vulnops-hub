from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.db import Base
from vulnops.cases.service import CaseService


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.cases.models  # noqa
    Base.metadata.create_all(bind=eng)
    return eng


def test_incomplete_scan_cannot_close_case():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1")
    for s in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        svc.transition(case.id, s, actor="a")

    # Incomplete coverage should not close
    result = svc.verify(
        case.id,
        method="scanner",
        evidence_ids=["ev_scan"],
        coverage={"status": "partial", "scope_version": "scan-001"},
        actor="verifier",
    )
    assert result.status == "insufficient_evidence"
    assert svc.get_case(case.id).status != "closed"
    assert svc.get_case(case.id).status == "awaiting_verification"
    session.close()


def test_failed_scan_cannot_close():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1")
    for s in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        svc.transition(case.id, s, actor="a")

    result = svc.verify(
        case.id,
        method="scanner",
        evidence_ids=["ev_scan"],
        coverage={"status": "failed", "scope_version": "scan-001"},
        actor="verifier",
    )
    assert result.status == "insufficient_evidence"
    assert svc.get_case(case.id).status == "awaiting_verification"
    session.close()


def test_valid_wazuh_inventory_can_close():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1", exposures=["exp1"])
    for s in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        svc.transition(case.id, s, actor="a")

    result = svc.verify(
        case.id,
        method="wazuh_inventory",
        evidence_ids=["ev_wazuh_879"],
        coverage={"status": "complete", "scope_version": "inventory-policy-3", "freshness_seconds": 900},
        actor="verifier",
    )
    assert result.status == "closed"
    assert svc.get_case(case.id).status == "closed"
    session.close()


def test_manual_attestation_cannot_close_without_approval():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    svc = CaseService(session)

    case = svc.create_case(organization_id="org1", title="test", owner_team="t1", priority="P1")
    for s in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        svc.transition(case.id, s, actor="a")

    result = svc.verify(
        case.id,
        method="manual_attestation",
        evidence_ids=["ev_manual"],
        coverage={"status": "complete"},
        actor="user",
    )
    # Manual attestation requires approval path, should not close directly
    assert result.status in ("requires_approval", "insufficient_evidence", "pending")
    assert svc.get_case(case.id).status != "closed"
    session.close()

"""Regression tests for PR #1 review feedback (P1 items)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from threading import Barrier

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.attributes import set_committed_value

from vulnops.cases.models import CaseStatus, RiskDecision
from vulnops.cases.service import CaseService
from vulnops.db import Base
from vulnops.db.models.audit_event import AuditEvent
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.matching.service import MatchingService
from vulnops.sbom.parser import ParsedComponent
from vulnops.sbom.service import SBOMService


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    import vulnops.cases.models
    import vulnops.db.models.audit_event
    import vulnops.db.models.outbox_event  # noqa

    Base.metadata.create_all(bind=eng)
    return eng


def _svc():
    eng = _engine()
    Session = sessionmaker(bind=eng)
    session = Session()
    return CaseService(session), session


def _file_engine(path):
    eng = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    import vulnops.cases.models
    import vulnops.db.models.audit_event
    import vulnops.db.models.outbox_event  # noqa

    Base.metadata.create_all(bind=eng)
    return eng


class _RaisingTZInfo(tzinfo):
    def __init__(self, exception_type: type[Exception]):
        self.exception_type = exception_type

    def utcoffset(self, dt):
        raise self.exception_type("malformed timezone")


class _RaisingAstimezoneDatetime(datetime):
    """A persisted-looking datetime whose timezone conversion is unusable."""

    def astimezone(self, tz=None):
        raise RuntimeError("malformed datetime conversion")


def test_verification_rejected_outside_awaiting_state():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    # Case is in new, not awaiting_verification
    with pytest.raises(ValueError, match="not allowed"):
        svc.verify(
            case.id,
            method="scanner",
            evidence_ids=["ev1"],
            coverage={"status": "complete", "scope_version": "scan-001"},
            actor="verifier",
        )
    # Must not have closed
    assert svc.get_case(case.id).status == "new"
    session.close()


def test_matching_rejects_different_package_name_same_ecosystem():
    svc = MatchingService()
    component = ParsedComponent(
        raw_name="left-pad",
        raw_version="1.0.0",
        purl="pkg:npm/left-pad@1.0.0",
        ecosystem="npm",
        normalized_name="left-pad",
        cpe=None,
        version_scheme="npm",
    )
    advisory = {
        "id": "CVE-2026-99999",
        "affected": [
            {
                "package": {"ecosystem": "npm", "purl": "pkg:npm/totally-different"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}
                ],
            }
        ],
    }
    result = svc.evaluate(
        component=component, advisory=advisory, asset_context={}, scanner_evidence=None
    )
    assert result.match_class != "deterministic"
    assert result.match_class == "candidate"
    assert result.should_create_case is False


def _request_risk_decision(svc: CaseService, case_id: str, requester: str = "alice"):
    return svc.create_risk_decision(
        case_id,
        type="risk_accepted",
        reason="need window",
        expires_at=datetime.now(UTC) + timedelta(days=10),
        evidence_ids=["ev1"],
        requested_by=requester,
        actor=requester,
        actor_provenance="authenticated_claim",
        actor_principal_type="human",
    )


def test_risk_request_stays_pending_and_does_not_change_case_state():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")

    decision = _request_risk_decision(svc, case.id)

    assert decision.status == "pending_approval"
    assert decision.requested_by == "alice"
    assert decision.approver is None
    assert svc.get_case(case.id).status == "triage"
    requested_audit = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "risk.decision.requested")
        .order_by(AuditEvent.created_at.desc())
    )
    assert requested_audit is not None
    assert requested_audit.actor == "alice"
    assert requested_audit.actor_provenance == "authenticated_claim"
    session.close()


def test_self_approval_rejected():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")

    decision = _request_risk_decision(svc, case.id)

    with pytest.raises(ValueError, match="self-approval"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="same person",
            actor="alice",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert decision.status == "pending_approval"
    assert svc.get_case(case.id).status == "triage"
    session.close()


def test_service_principal_cannot_approve_even_with_spoofed_capability():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)

    with pytest.raises(ValueError, match="service principals"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="service must not approve",
            actor="ci-service",
            actor_principal_type="service",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert decision.status == "pending_approval"
    assert svc.get_case(case.id).status == "triage"
    session.close()


def test_authenticated_approval_records_claim_actor_and_changes_case_state():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = svc.create_risk_decision(
        case.id,
        type="false_positive",
        reason="scanner mis-identified",
        expires_at=datetime.now(UTC) + timedelta(days=10),
        evidence_ids=["ev1"],
        requested_by="alice",
        actor="alice",
        actor_provenance="authenticated_claim",
        actor_principal_type="human",
    )

    decision = svc.approve_risk_decision(
        decision.id,
        outcome="approve",
        reason="independent review",
        actor="bob-approver",
        actor_principal_type="human",
        actor_roles={"risk_approver"},
        actor_capabilities={"risk:approve"},
        actor_provenance="authenticated_claim",
    )

    assert decision.status == "approved"
    assert decision.approver == "bob-approver"
    assert decision.approver_role == "risk_approver"
    assert decision.approver_provenance == "authenticated_claim"
    assert decision.decided_at is not None
    assert svc.get_case(case.id).status == CaseStatus.NOT_APPLICABLE
    approval_audit = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "risk.false_positive.accepted")
        .order_by(AuditEvent.created_at.desc())
    )
    assert approval_audit is not None
    assert approval_audit.actor == "bob-approver"
    assert approval_audit.actor_provenance == "authenticated_claim"
    session.close()


def test_risk_request_validation_rejects_unsupported_or_incomplete_values():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    valid = {
        "type": "risk_accepted",
        "reason": "need window",
        "expires_at": datetime.now(UTC) + timedelta(days=1),
        "evidence_ids": ["ev1"],
    }
    invalid_cases = [
        ({**valid, "type": "unsupported"}, "unsupported risk decision type"),
        ({**valid, "reason": "   "}, "risk decision reason is required"),
        ({**valid, "evidence_ids": []}, "risk decision evidence_ids must contain at least one"),
        ({**valid, "evidence_ids": ["  "]}, "risk decision evidence_ids must contain only"),
        ({**valid, "expires_at": None}, "risk decision expires_at is required"),
        (
            {**valid, "expires_at": datetime.now(UTC).replace(tzinfo=None)},
            "risk decision expires_at must be timezone-aware",
        ),
        (
            {**valid, "expires_at": datetime.now(UTC) - timedelta(seconds=1)},
            "risk decision expires_at must be in the future",
        ),
    ]
    for payload, message in invalid_cases:
        with pytest.raises(ValueError, match=message):
            svc.create_risk_decision(
                case.id,
                requested_by="alice",
                actor="alice",
                actor_provenance="authenticated_claim",
                actor_principal_type="human",
                **payload,
            )
    assert svc.list_risk_decisions(case.id) == []
    session.close()


def test_approval_rejects_decision_without_evidence():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    decision.evidence_ids = []
    session.commit()

    with pytest.raises(ValueError, match="evidence_ids"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="independent review",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert svc.get_case(case.id).status == CaseStatus.TRIAGE
    assert (
        session.scalar(select(OutboxEvent).where(OutboxEvent.aggregate_id == decision.id))
        is not None
    )
    assert (
        session.scalar(select(AuditEvent).where(AuditEvent.action == "risk.decision.requested"))
        is not None
    )
    session.close()


def test_approval_rejects_expired_decision_without_mutating_workflow():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    decision.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    session.commit()
    before_audits = session.scalar(select(func.count()).select_from(AuditEvent))
    before_outbox = session.scalar(select(func.count()).select_from(OutboxEvent))
    before_case = (svc.get_case(case.id).status, svc.get_case(case.id).version)

    with pytest.raises(ValueError, match="risk decision expires_at must be in the future"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="independent review",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert (svc.get_case(case.id).status, svc.get_case(case.id).version) == before_case
    unchanged = svc.get_risk_decision(decision.id)
    assert unchanged.status == "pending_approval"
    assert unchanged.approver is None
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == before_audits
    assert session.scalar(select(func.count()).select_from(OutboxEvent)) == before_outbox
    session.close()


def test_non_utc_expiry_round_trip_rejects_after_true_utc_instant(monkeypatch, tmp_path):
    engine = _file_engine(tmp_path / "offset-expiry.db")
    Session = sessionmaker(bind=engine)
    session = Session()
    svc = CaseService(session)
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    expiry = datetime(2030, 1, 1, 18, 0, tzinfo=timezone(timedelta(hours=8)))
    decision = svc.create_risk_decision(
        case.id,
        type="risk_accepted",
        reason="offset expiry",
        expires_at=expiry,
        evidence_ids=["ev-offset"],
        requested_by="alice",
        actor="alice",
        actor_provenance="authenticated_claim",
        actor_principal_type="human",
    )
    session.expire_all()
    round_tripped = svc.get_risk_decision(decision.id)
    before_case = (svc.get_case(case.id).status, svc.get_case(case.id).version)
    before_audits = session.scalar(select(func.count()).select_from(AuditEvent))
    before_outbox = session.scalar(select(func.count()).select_from(OutboxEvent))
    monkeypatch.setattr(
        "vulnops.cases.service._utcnow",
        lambda: datetime(2030, 1, 1, 10, 0, 1, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="risk decision expires_at must be in the future"):
        svc.approve_risk_decision(
            round_tripped.id,
            outcome="approve",
            reason="review after true expiry",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert round_tripped.expires_at == expiry.astimezone(UTC)
    assert (svc.get_case(case.id).status, svc.get_case(case.id).version) == before_case
    unchanged = svc.get_risk_decision(decision.id)
    assert unchanged.status == "pending_approval"
    assert unchanged.approver is None
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == before_audits
    assert session.scalar(select(func.count()).select_from(OutboxEvent)) == before_outbox
    session.close()


def test_aware_non_utc_orm_expiry_is_canonical_for_read_and_approval_outbox():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    non_utc = datetime(2030, 1, 1, 18, 0, tzinfo=timezone(timedelta(hours=8)))

    # Simulate an ORM-loaded aware value returned by a PostgreSQL/session timezone.
    set_committed_value(decision, "expires_at", non_utc)
    assert decision not in session.dirty

    loaded = svc.get_risk_decision(decision.id)
    assert loaded.expires_at == datetime(2030, 1, 1, 10, 0, tzinfo=UTC)
    assert loaded.expires_at.tzinfo is UTC
    assert loaded not in session.dirty

    approved = svc.approve_risk_decision(
        decision.id,
        outcome="approve",
        reason="independent review",
        actor="bob-approver",
        actor_principal_type="human",
        actor_roles={"risk_approver"},
        actor_capabilities={"risk:approve"},
        actor_provenance="authenticated_claim",
    )
    assert approved.status == "approved"
    approval_outbox = session.scalar(
        select(OutboxEvent)
        .where(OutboxEvent.aggregate_id == decision.id)
        .where(OutboxEvent.event_type == "vulnops.risk-decision.accepted.v1")
    )
    assert approval_outbox is not None
    assert approval_outbox.payload["expires_at"] == "2030-01-01T10:00:00+00:00"
    session.close()


def test_already_utc_orm_expiry_stays_clean(monkeypatch):
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    canonical = datetime(2030, 1, 1, 10, 0, tzinfo=UTC)
    set_committed_value(decision, "expires_at", canonical)

    def unexpected_write(*args, **kwargs):
        raise AssertionError("already canonical UTC value must not be rewritten")

    monkeypatch.setattr("vulnops.cases.service.set_committed_value", unexpected_write)
    loaded = svc.get_risk_decision(decision.id)
    assert loaded.expires_at is canonical
    assert loaded not in session.dirty
    session.close()


def test_malformed_orm_expiry_returns_stable_domain_error_without_mutation():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    set_committed_value(decision, "expires_at", "not-a-datetime")
    before_case = (svc.get_case(case.id).status, svc.get_case(case.id).version)
    before_audits = session.scalar(select(func.count()).select_from(AuditEvent))
    before_outbox = session.scalar(select(func.count()).select_from(OutboxEvent))

    with pytest.raises(ValueError, match="risk decision expires_at must be timezone-aware"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="independent review",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert (svc.get_case(case.id).status, svc.get_case(case.id).version) == before_case
    persisted = session.get(RiskDecision, decision.id)
    assert persisted is not None
    assert persisted.status == "pending_approval"
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == before_audits
    assert session.scalar(select(func.count()).select_from(OutboxEvent)) == before_outbox
    session.close()


@pytest.mark.parametrize("exception_type", [RuntimeError, TypeError, ValueError])
def test_malformed_tzinfo_expiry_returns_stable_domain_error_without_mutation(exception_type):
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    malformed = datetime(2030, 1, 1, 10, tzinfo=_RaisingTZInfo(exception_type))
    set_committed_value(decision, "expires_at", malformed)
    before_case = (svc.get_case(case.id).status, svc.get_case(case.id).version)
    before_audits = session.scalar(select(func.count()).select_from(AuditEvent))
    before_outbox = session.scalar(select(func.count()).select_from(OutboxEvent))

    with pytest.raises(ValueError, match="risk decision expires_at must be timezone-aware"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="review malformed timezone",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert (svc.get_case(case.id).status, svc.get_case(case.id).version) == before_case
    persisted = session.get(RiskDecision, decision.id)
    assert persisted is not None
    assert persisted.status == "pending_approval"
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == before_audits
    assert session.scalar(select(func.count()).select_from(OutboxEvent)) == before_outbox
    session.close()


def test_unnormalizable_datetime_expiry_returns_stable_domain_error_without_mutation():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    malformed = _RaisingAstimezoneDatetime(2030, 1, 1, 10, tzinfo=UTC)
    set_committed_value(decision, "expires_at", malformed)
    before_case = (svc.get_case(case.id).status, svc.get_case(case.id).version)
    before_audits = session.scalar(select(func.count()).select_from(AuditEvent))
    before_outbox = session.scalar(select(func.count()).select_from(OutboxEvent))

    with pytest.raises(ValueError, match="risk decision expires_at must be timezone-aware"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="review unnormalizable expiry",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )

    assert (svc.get_case(case.id).status, svc.get_case(case.id).version) == before_case
    persisted = session.get(RiskDecision, decision.id)
    assert persisted is not None
    assert persisted.status == "pending_approval"
    assert persisted.approver is None
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == before_audits
    assert session.scalar(select(func.count()).select_from(OutboxEvent)) == before_outbox
    session.close()


def test_approval_rolls_back_conditional_update_execution_errors(monkeypatch):
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)
    original_execute = session.execute
    failed = False

    def fail_once(statement, *args, **kwargs):
        nonlocal failed
        if not failed and statement.__class__.__name__ == "Update":
            failed = True
            raise RuntimeError("injected database execution failure")
        return original_execute(statement, *args, **kwargs)

    monkeypatch.setattr(session, "execute", fail_once)
    with pytest.raises(RuntimeError, match="injected database execution failure"):
        svc.approve_risk_decision(
            decision.id,
            outcome="approve",
            reason="first attempt",
            actor="bob-approver",
            actor_principal_type="human",
            actor_roles={"risk_approver"},
            actor_capabilities={"risk:approve"},
            actor_provenance="authenticated_claim",
        )
    assert not session.in_transaction()

    approved = svc.approve_risk_decision(
        decision.id,
        outcome="approve",
        reason="retry after rollback",
        actor="bob-approver",
        actor_principal_type="human",
        actor_roles={"risk_approver"},
        actor_capabilities={"risk:approve"},
        actor_provenance="authenticated_claim",
    )
    assert approved.status == "approved"
    session.close()


def test_concurrent_approval_has_one_winner_and_one_stable_conflict(tmp_path):
    engine = _file_engine(tmp_path / "approval-concurrency.db")
    Session = sessionmaker(bind=engine)
    setup = Session()
    setup_svc = CaseService(setup)
    case = setup_svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    setup_svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(setup_svc, case.id)
    decision_id = decision.id
    setup.close()
    barrier = Barrier(2)

    def approve(actor: str):
        session = Session()
        try:
            barrier.wait(timeout=10)
            result = CaseService(session).approve_risk_decision(
                decision_id,
                outcome="approve",
                reason=f"review by {actor}",
                actor=actor,
                actor_principal_type="human",
                actor_roles={"risk_approver"},
                actor_capabilities={"risk:approve"},
                actor_provenance="authenticated_claim",
            )
            return ("success", result.approver)
        except Exception as exc:
            return ("error", str(exc))
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(approve, ("bob-1", "bob-2")))

    assert [kind for kind, _ in outcomes].count("success") == 1
    errors = [message for kind, message in outcomes if kind == "error"]
    assert len(errors) == 1
    assert "risk decision conflict" in errors[0]

    verify = Session()
    final_decision = verify.get(type(decision), decision_id)
    final_case = verify.get(type(case), case.id)
    approvals = list(
        verify.scalars(
            select(AuditEvent)
            .where(AuditEvent.subject_id == decision_id)
            .where(AuditEvent.action.in_(("risk.accepted", "risk.decision.rejected")))
        )
    )
    outbox = list(
        verify.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.aggregate_id == decision_id)
            .where(OutboxEvent.event_type == "vulnops.risk-decision.accepted.v1")
        )
    )
    assert final_decision.status == "approved"
    assert final_case.status == CaseStatus.RISK_ACCEPTED
    assert final_case.version == 3
    assert len(approvals) == 1
    assert len(outbox) == 1
    verify.close()


def test_workflow_trace_ids_are_preserved_in_audit_and_outbox(tmp_path):
    engine = _file_engine(tmp_path / "trace.db")
    Session = sessionmaker(bind=engine)
    session = Session()
    svc = CaseService(session)
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(
        case.id,
        "triage",
        actor="alice",
        actor_provenance="authenticated_claim",
        actor_principal_type="human",
        actor_roles={"owner"},
        actor_scopes={"case:write"},
        request_id="req-transition",
        correlation_id="corr-transition",
    )
    decision = svc.create_risk_decision(
        case.id,
        type="risk_accepted",
        reason="need window",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        evidence_ids=["ev1"],
        requested_by="alice",
        actor="alice",
        actor_provenance="authenticated_claim",
        actor_principal_type="human",
        actor_roles={"owner"},
        actor_scopes={"risk:request"},
        request_id="req-request",
        correlation_id="corr-request",
    )
    svc.approve_risk_decision(
        decision.id,
        outcome="approve",
        reason="independent review",
        actor="bob",
        actor_principal_type="human",
        actor_roles={"risk_approver"},
        actor_capabilities={"risk:approve"},
        actor_provenance="authenticated_claim",
        actor_scopes={"risk:approve"},
        request_id="req-approval",
        correlation_id="corr-approval",
    )
    transition_audit = session.scalar(
        select(AuditEvent).where(AuditEvent.correlation_id == "corr-transition")
    )
    request_audit = session.scalar(
        select(AuditEvent).where(AuditEvent.correlation_id == "corr-request")
    )
    approval_audit = session.scalar(
        select(AuditEvent).where(AuditEvent.correlation_id == "corr-approval")
    )
    assert transition_audit.request_id == "req-transition"
    assert request_audit.request_id == "req-request"
    assert approval_audit.request_id == "req-approval"
    assert approval_audit.actor_principal_type == "human"
    assert approval_audit.actor_roles == ["risk_approver"]
    assert approval_audit.actor_scopes == ["risk:approve"]
    approval_outbox = session.scalar(
        select(OutboxEvent).where(OutboxEvent.correlation_id == "corr-approval")
    )
    assert approval_outbox.payload["request_id"] == "req-approval"
    assert approval_outbox.payload["correlation_id"] == "corr-approval"
    assert approval_outbox.payload["actor"] == "bob"
    assert approval_outbox.payload["organization_id"] == "org1"
    assert approval_outbox.payload["principal_type"] == "human"
    assert approval_outbox.payload["roles"] == ["risk_approver"]
    assert approval_outbox.payload["scopes"] == ["risk:approve"]

    verification_case = svc.create_case(
        organization_id="org1", title="verification", owner_team="t1", priority="P1"
    )
    for target in ("triage", "assigned", "in_progress", "awaiting_verification"):
        svc.transition(verification_case.id, target, actor="alice")
    svc.verify(
        verification_case.id,
        method="scanner",
        evidence_ids=["ev-scan"],
        coverage={"status": "complete", "scope_version": "scan-001"},
        actor="alice",
        actor_provenance="authenticated_claim",
        actor_principal_type="human",
        actor_roles={"owner"},
        actor_scopes={"verification:write"},
        request_id="req-verification",
        correlation_id="corr-verification",
    )
    verification_audit = session.scalar(
        select(AuditEvent).where(AuditEvent.correlation_id == "corr-verification")
    )
    verification_outbox = session.scalar(
        select(OutboxEvent).where(OutboxEvent.correlation_id == "corr-verification")
    )
    assert verification_audit.request_id == "req-verification"
    assert verification_outbox.payload["principal_type"] == "human"
    assert verification_outbox.payload["request_id"] == "req-verification"
    session.close()


def test_authenticated_rejection_records_decision_without_changing_case_state():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = _request_risk_decision(svc, case.id)

    decision = svc.approve_risk_decision(
        decision.id,
        outcome="reject",
        reason="insufficient evidence",
        actor="bob-approver",
        actor_principal_type="human",
        actor_roles={"security_lead"},
        actor_capabilities={"risk:approve"},
        actor_provenance="authenticated_claim",
    )

    assert decision.status == "rejected"
    assert decision.approver == "bob-approver"
    assert decision.approver_role == "security_lead"
    assert decision.decided_at is not None
    assert svc.get_case(case.id).status == CaseStatus.TRIAGE
    rejection_audit = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "risk.decision.rejected")
        .order_by(AuditEvent.created_at.desc())
    )
    assert rejection_audit is not None
    assert rejection_audit.subject_id == decision.id
    assert rejection_audit.actor == "bob-approver"
    session.close()


def test_not_affected_maps_to_not_applicable():
    svc, session = _svc()
    case = svc.create_case(organization_id="org1", title="t", owner_team="t1", priority="P1")
    svc.transition(case.id, "triage", actor="analyst")
    decision = svc.create_risk_decision(
        case.id,
        type="not_affected",
        reason="VEX says not affected",
        expires_at=datetime.now(UTC) + timedelta(days=10),
        evidence_ids=["ev-vex"],
        requested_by="alice",
        actor="alice",
        actor_provenance="legacy_request",
    )
    decision = svc.approve_risk_decision(
        decision.id,
        outcome="approve",
        reason="independent review",
        actor="bob-approver",
        actor_principal_type="human",
        actor_roles={"security_lead"},
        actor_capabilities={"risk:approve"},
        actor_provenance="authenticated_claim",
    )
    assert decision.status == "approved"
    assert svc.get_case(case.id).status == CaseStatus.NOT_APPLICABLE
    session.close()


def test_sbom_persists_raw_bytes_and_uses_configured_bucket(tmp_path, monkeypatch):
    import vulnops.sbom.models  # noqa
    from vulnops.config import get_settings

    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    Session = sessionmaker(bind=eng)
    session = Session()

    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    try:
        svc = SBOMService(session)
        raw = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "urllib3",
                    "version": "1.26.18",
                    "purl": "pkg:pypi/urllib3@1.26.18",
                }
            ],
        }
        result = svc.ingest(raw, organization_id="org1")
        bucket = get_settings().object_storage_bucket
        # Verify backing file exists and digest matches
        import hashlib
        import json

        raw_bytes = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw_bytes).hexdigest()
        expected = tmp_path / "storage" / "sbom" / "org1" / f"{digest}.json"
        assert expected.exists()
        assert expected.read_bytes() == raw_bytes
        assert result["content_sha256"] == digest
        # URI must use configured bucket, not a hard-coded default
        from vulnops.sbom.models import SbomDocument

        doc = session.get(SbomDocument, result["id"])
        assert doc is not None
        assert doc.object_uri == f"s3://{bucket}/sbom/org1/{digest}.json"
    finally:
        get_settings.cache_clear()
    session.close()


def test_worker_consumes_redis_queue(monkeypatch):
    from vulnops.config import get_settings
    from vulnops.workers.ingestion import IngestionWorker

    seen = []

    def handler(session, payload, org, key):
        seen.append((payload, org, key))
        return {"ok": True}

    monkeypatch.setenv("REDIS_URL", "redis://test:6379/0")
    get_settings.cache_clear()
    try:
        worker = IngestionWorker(session_factory=lambda: None)  # type: ignore[arg-type]
        worker.register("defectdojo", handler)

        class FakeRedis:
            def __init__(self, jobs):
                self.jobs = list(jobs)

            def ping(self):
                return True

            def brpop(self, key, timeout=1):
                assert key == "vulnops:ingest"
                if not self.jobs:
                    return None
                return (key, self.jobs.pop(0))

        import json as _json

        job = {"source": "defectdojo", "payload": {"id": 1}, "organization_id": "org1"}
        fake = FakeRedis([_json.dumps(job).encode()])

        try:
            import redis  # type: ignore

            orig_from_url = redis.from_url
            redis.from_url = lambda *a, **k: fake
            try:
                worker.run_forever(poll_interval=0.01, max_iterations=2)
            finally:
                redis.from_url = orig_from_url
        except ImportError:
            pytest.skip("redis not installed")
    finally:
        get_settings.cache_clear()
    assert len(seen) == 1
    assert seen[0][0] == {"id": 1}

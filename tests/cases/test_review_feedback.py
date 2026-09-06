"""Regression tests for PR #1 review feedback (P1 items)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from vulnops.cases.models import CaseStatus
from vulnops.cases.service import CaseService
from vulnops.db import Base
from vulnops.db.models.audit_event import AuditEvent
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

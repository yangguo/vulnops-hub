"""Orchestration worker tests: outbox events -> exposures -> auto cases."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import vulnops.intelligence.models  # register intel metadata
import vulnops.workers.orchestration  # noqa: F401  (register matching/cases metadata)
from vulnops.config import Settings
from vulnops.db import Base
from vulnops.db.models.outbox_event import OutboxEvent


def _settings(**overrides) -> Settings:
    """Settings instance safe for unit tests (no test bypass needed here)."""

    defaults: dict = {
        "oidc_issuer_url": "http://127.0.0.1:8082/realms/vulnops",
        "oidc_audience": "vulnops-api",
    }
    defaults.update(overrides)
    return Settings(**defaults)


@pytest.fixture()
def db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture()
def db_no_autoflush():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    session = factory()
    yield session
    session.close()


def _outbox(event_type: str, payload: dict) -> OutboxEvent:
    return OutboxEvent(
        id=f"evt_{uuid.uuid4().hex[:12]}",
        aggregate_type="test",
        aggregate_id="agg-1",
        event_type=event_type,
        payload=payload,
        created_at=datetime.now(UTC),
    )


def test_orchestration_settings_defaults():
    s = _settings()
    assert s.orchestrator_poll_interval_seconds == 5.0
    assert s.orchestrator_batch_size == 50
    assert s.orchestrator_max_attempts == 8
    assert s.case_auto_create_enabled is True
    assert s.default_case_owner_team == "unassigned"


def test_claim_events_returns_undelivered_oldest_first(db):
    from vulnops.workers.orchestration import claim_events

    old = _outbox("t.a.v1", {})
    db.add(old)
    db.commit()
    new = _outbox("t.b.v1", {})
    new.created_at = old.created_at + timedelta(seconds=1)
    db.add(new)
    db.commit()
    claimed = claim_events(db, batch_size=10, max_attempts=8)
    assert [e.id for e in claimed] == [old.id, new.id]


def test_claim_events_skips_delivered_and_poison(db):
    from vulnops.workers.orchestration import claim_events

    done = _outbox("t.a.v1", {})
    done.delivered_at = datetime.now(UTC)
    poison = _outbox("t.b.v1", {})
    poison.attempts = 8
    db.add_all([done, poison])
    db.commit()
    assert claim_events(db, batch_size=10, max_attempts=8) == []


def test_complete_event_marks_delivered(db):
    from vulnops.workers.orchestration import complete_event

    ev = _outbox("t.a.v1", {})
    db.add(ev)
    db.commit()
    complete_event(db, ev)
    assert ev.delivered_at is not None


def test_fail_event_increments_attempts(db):
    from vulnops.workers.orchestration import fail_event

    ev = _outbox("t.a.v1", {})
    db.add(ev)
    db.commit()
    fail_event(db, ev, max_attempts=8)
    assert ev.attempts == 1


def test_fail_event_logs_at_poison_cap(db, caplog):
    from vulnops.workers.orchestration import claim_events, fail_event

    ev = _outbox("t.a.v1", {})
    db.add(ev)
    db.commit()
    with caplog.at_level(logging.ERROR):
        caplog.clear()
        for _ in range(8):
            fail_event(db, ev, max_attempts=8)
    assert ev.attempts == 8
    poison_logs = [
        r for r in caplog.records if "dead-lettered" in r.getMessage() and ev.id in r.getMessage()
    ]
    assert len(poison_logs) == 1
    assert poison_logs[0].levelno == logging.ERROR
    # The dead-lettered event is no longer claimable.
    assert claim_events(db, batch_size=10, max_attempts=8) == []


def test_upsert_exposure_creates_then_replays_without_duplicates(db):
    from vulnops.matching.models import Exposure, MatchEvidence
    from vulnops.workers.orchestration import upsert_exposure

    exp, created = upsert_exposure(
        db,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-0001",
        match_class="deterministic",
        confidence=0.93,
        detection_context="sbom:sbom_1",
        component_occurrence_id="occ_1",
        matched_rules=["osv.purl-range"],
        evidence_refs=["ss_1"],
        matcher_version="2026.1",
        evidence_ref="ss_1",
    )
    db.commit()
    assert created is True
    assert exp.state == "active"

    exp2, created2 = upsert_exposure(
        db,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-0001",
        match_class="deterministic",
        confidence=0.93,
        detection_context="sbom:sbom_1",
        component_occurrence_id="occ_1",
        matcher_version="2026.1",
        evidence_ref="ss_1",
    )
    db.commit()
    assert created2 is False
    assert exp2.id == exp.id
    assert db.query(Exposure).count() == 1
    assert db.query(MatchEvidence).count() == 1


def test_upsert_exposure_state_follows_match_class(db):
    from vulnops.workers.orchestration import upsert_exposure

    cand, _ = upsert_exposure(
        db,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-0002",
        match_class="candidate",
        confidence=0.35,
        detection_context="wazuh:000",
        matcher_version="2026.1",
    )
    na, _ = upsert_exposure(
        db,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-0003",
        match_class="not_affected",
        confidence=0.85,
        detection_context="sbom:sbom_2",
        matcher_version="2026.1",
    )
    db.commit()
    assert cand.state == "candidate"
    assert na.state == "not_affected"


def test_upsert_exposure_dedups_evidence_without_autoflush(db_no_autoflush):
    from vulnops.matching.models import Exposure, MatchEvidence
    from vulnops.workers.orchestration import upsert_exposure

    upsert_exposure(
        db_no_autoflush,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-0001",
        match_class="deterministic",
        confidence=0.93,
        detection_context="sbom:sbom_1",
        component_occurrence_id="occ_1",
        matcher_version="2026.1",
        evidence_ref="ss_1",
    )
    upsert_exposure(
        db_no_autoflush,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-0001",
        match_class="deterministic",
        confidence=0.93,
        detection_context="sbom:sbom_1",
        component_occurrence_id="occ_1",
        matcher_version="2026.1",
        evidence_ref="ss_1",
    )
    db_no_autoflush.commit()
    assert db_no_autoflush.query(Exposure).count() == 1
    assert db_no_autoflush.query(MatchEvidence).count() == 1


class _NeverClient:
    def post(self, *args, **kwargs):
        raise RuntimeError("network disabled in unit tests")


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _RecordingClient:
    """Captures POST requests; replays scripted payloads/exceptions in order."""

    def __init__(self, responses):
        self.requests: list[dict] = []
        self._responses = list(responses)

    def post(self, url, json=None, **kwargs):
        self.requests.append({"url": url, "json": json})
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return _FakeResponse(item)


def test_osv_lookup_batch_records_carry_query_index():
    from vulnops.intelligence.osv import OSVAdapter

    fixture = {
        "results": [
            {"vulns": [{"id": "CVE-2026-1111", "affected": []}]},
            {"vulns": []},
            {"vulns": [{"id": "CVE-2026-2222", "affected": []}]},
        ]
    }
    records = OSVAdapter().lookup_batch(
        [
            {"purl": "pkg:pypi/a", "version": "1"},
            {"purl": "pkg:pypi/b", "version": "2"},
            {"purl": "pkg:pypi/c", "version": "3"},
        ],
        raw_fixture=fixture,
    )
    assert [r.retrieval_metadata["query_index"] for r in records] == [0, 2]


def test_osv_lookup_batch_without_fixture_raises_without_network():
    from vulnops.intelligence.osv import OSVAdapter

    with pytest.raises(RuntimeError):
        OSVAdapter(http_client=_NeverClient()).lookup_batch(
            [{"purl": "pkg:pypi/a", "version": "1"}]
        )


def test_osv_live_query_strips_purl_version_and_returns_full_records():
    from vulnops.intelligence.osv import OSVAdapter

    client = _RecordingClient(
        [
            {
                "vulns": [
                    {
                        "id": "GHSA-2xpw-w6gg-jr37",
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "purl": "pkg:pypi/urllib3"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "1.0"}, {"fixed": "2.6.0"}],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    )
    records = OSVAdapter(http_client=client).lookup_batch(
        [{"purl": "pkg:pypi/urllib3@1.26.17", "version": "1.26.17"}]
    )

    # One POST /v1/query per component, purl stripped of its version qualifier.
    assert len(client.requests) == 1
    assert client.requests[0]["url"] == "https://api.osv.dev/v1/query"
    assert client.requests[0]["json"]["package"]["purl"] == "pkg:pypi/urllib3"
    assert client.requests[0]["json"]["version"] == "1.26.17"
    # Full /v1/query records keep affected ranges and per-component provenance.
    assert len(records) == 1
    assert records[0].vulnerability_id == "GHSA-2xpw-w6gg-jr37"
    assert records[0].affected_ranges == [
        {
            "ecosystem": "PyPI",
            "purl": "pkg:pypi/urllib3",
            "type": "ECOSYSTEM",
            "introduced": "1.0",
            "fixed": "2.6.0",
        }
    ]
    assert records[0].retrieval_metadata["query_index"] == 0
    assert records[0].source_url == "https://api.osv.dev/v1/query"


def test_osv_live_query_preserves_namespace_purl():
    from vulnops.intelligence.osv import OSVAdapter

    client = _RecordingClient([{"vulns": []}])
    OSVAdapter(http_client=client).lookup_batch(
        [{"purl": "pkg:rpm/fedora/curl@7.0.1-1.el9", "version": "7.0.1-1.el9"}]
    )
    # Only the name-segment @version is dropped; the rpm namespace survives.
    assert client.requests[0]["json"]["package"]["purl"] == "pkg:rpm/fedora/curl"


def test_osv_live_query_all_fail_raises_and_partial_fail_continues():
    from vulnops.intelligence.osv import OSVAdapter

    # Every component fails -> the whole batch raises so the orchestrator's
    # fail_event path retries the event; source health is stale.
    all_fail = _RecordingClient([RuntimeError("400 Bad Request"), RuntimeError("429")])
    adapter = OSVAdapter(http_client=all_fail)
    with pytest.raises(RuntimeError):
        adapter.lookup_batch(
            [
                {"purl": "pkg:pypi/a@1.0", "version": "1.0"},
                {"purl": "pkg:pypi/b@2.0", "version": "2.0"},
            ]
        )
    assert adapter.get_health().freshness == "stale"

    # One component fails -> it is skipped, later components still get queried
    # with their own query_index, and health stays stale.
    partial = _RecordingClient(
        [RuntimeError("400 Bad Request"), {"vulns": [{"id": "CVE-2026-2222", "affected": []}]}]
    )
    adapter = OSVAdapter(http_client=partial)
    records = adapter.lookup_batch(
        [
            {"purl": "pkg:pypi/broken@1.0", "version": "1.0"},
            {"purl": "pkg:pypi/good@2.0", "version": "2.0"},
        ]
    )
    assert [r.vulnerability_id for r in records] == ["CVE-2026-2222"]
    assert records[0].retrieval_metadata["query_index"] == 1
    assert adapter.get_health().freshness == "stale"


def _sbom_event(sbom_id: str = "sbom_1", org: str = "org-demo"):
    return _outbox(
        "vulnops.sbom.processed.v1",
        {"sbom_id": sbom_id, "organization_id": org, "component_count": 1},
    )


def _occurrence(sbom_id: str = "sbom_1", purl: str = "pkg:pypi/urllib3@1.26.17"):
    from vulnops.sbom.models import ComponentOccurrence

    name = purl.split("/")[-1].split("@")[0]
    return ComponentOccurrence(
        id=f"occ_{uuid.uuid4().hex[:8]}",
        sbom_id=sbom_id,
        purl=purl,
        ecosystem="pypi",
        normalized_name=name,
        raw_name=name,
        raw_version=purl.split("@")[-1],
        version_scheme="pypi",
    )


def _osv_fixture_for(purl_base: str, cve: str, fixed: str) -> dict:
    """One OSV query -> one vuln with an in-range ECOSYSTEM advisory."""

    return {
        "results": [
            {
                "vulns": [
                    {
                        "id": cve,
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "purl": purl_base},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }


class _FixtureOSV:
    """OSV stand-in that always returns the urllib3 in-range fixture."""

    def __init__(self, cve: str = "CVE-2026-1234", fixed: str = "1.26.19"):
        self.cve = cve
        self.fixed = fixed

    def lookup_batch(self, components, **kwargs):
        from vulnops.intelligence.osv import OSVAdapter

        return OSVAdapter().lookup_batch(
            components,
            raw_fixture=_osv_fixture_for("pkg:pypi/urllib3", self.cve, self.fixed),
        )


def _orch(db, settings=None, osv=None):
    from vulnops.workers.orchestration import OutboxOrchestrator

    return OutboxOrchestrator(
        session_factory=lambda: db,
        osv=osv or _FixtureOSV(),
        settings=settings or _settings(),
    )


def test_sbom_intel_deferred_integrity_still_creates_exposure(db, monkeypatch):
    """Flush-time IntegrityError on cache session must not fail the outbox handler."""

    from sqlalchemy.orm import sessionmaker

    import vulnops.intelligence.persistence as intel_persistence
    from vulnops.intelligence.models import VulnerabilityAlias
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import OutboxOrchestrator, claim_events

    eng = db.get_bind()
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)

    def _deferred_alias_conflict(cache_session, _records):
        cache_session.add(
            VulnerabilityAlias(
                id="alias_dup_a",
                vulnerability_id="CVE-2026-1234",
                alias="GHSA-deferred-dup",
                source="osv",
            )
        )
        cache_session.add(
            VulnerabilityAlias(
                id="alias_dup_b",
                vulnerability_id="CVE-2026-1234",
                alias="GHSA-deferred-dup",
                source="osv",
            )
        )

    monkeypatch.setattr(intel_persistence, "upsert_advisory_records", _deferred_alias_conflict)

    work = factory()
    work.add(_occurrence())
    work.add(_sbom_event("sbom_1"))
    work.commit()

    orch = OutboxOrchestrator(
        session_factory=factory,
        osv=_FixtureOSV(),
        settings=_settings(),
    )
    event = claim_events(work, batch_size=10, max_attempts=8)[0]
    orch.process_event(work, event)

    exposures = work.query(Exposure).all()
    assert len(exposures) == 1
    assert exposures[0].match_class == "deterministic"
    assert event.delivered_at is not None
    assert event.attempts == 0


def test_sbom_intel_persist_failure_still_creates_exposure(db, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import OutboxOrchestrator, claim_events

    def _fail_upsert(*_args, **_kwargs):
        raise RuntimeError("intel cache unavailable")

    monkeypatch.setattr(
        "vulnops.intelligence.persistence.upsert_advisory_records",
        _fail_upsert,
    )

    eng = db.get_bind()
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    work = factory()
    work.add(_occurrence())
    work.add(_sbom_event("sbom_1"))
    work.commit()

    orch = OutboxOrchestrator(
        session_factory=factory,
        osv=_FixtureOSV(),
        settings=_settings(),
    )
    event = claim_events(work, batch_size=10, max_attempts=8)[0]
    orch.process_event(work, event)

    exposures = work.query(Exposure).all()
    assert len(exposures) == 1
    assert exposures[0].match_class == "deterministic"
    assert event.delivered_at is not None
    assert event.attempts == 0


def test_sbom_event_creates_deterministic_exposure_and_case(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    occ = _occurrence()
    db.add(occ)
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = _orch(db)
    event = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, event)

    exposures = db.query(Exposure).all()
    assert len(exposures) == 1
    assert exposures[0].match_class == "deterministic"
    assert exposures[0].state == "active"
    assert exposures[0].component_occurrence_id == occ.id
    assert exposures[0].priority in ("P1", "P2", "P3")
    assert exposures[0].policy_version is not None

    case = db.query(RemediationCase).one()
    assert case.status == "new"
    assert case.priority == exposures[0].priority
    assert case.exposures == [exposures[0].id]
    assert event.delivered_at is not None


def test_sbom_case_owner_uses_linked_business_service(db):
    from vulnops.assets.models import Asset
    from vulnops.cases.models import RemediationCase
    from vulnops.services.models import BusinessService
    from vulnops.workers.orchestration import claim_events

    db.add(
        BusinessService(
            id="svc-orchestration",
            organization_id="org-demo",
            name="Payments",
            owner_team="payments-platform",
        )
    )
    db.add(
        Asset(
            id="asset-orchestration",
            organization_id="org-demo",
            name="payments-01",
            business_service_id="svc-orchestration",
        )
    )
    occurrence = _occurrence()
    occurrence.asset_id = "asset-orchestration"
    db.add(occurrence)
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = _orch(db)
    event = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, event)

    case = db.query(RemediationCase).one()
    assert case.owner_team == "payments-platform"
    assert case.ownership_escalated is False


def test_sbom_event_replay_does_not_duplicate_case(db):
    from vulnops.cases.models import CaseExposure, RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_occurrence())
    db.add(_sbom_event("sbom_1"))
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = _orch(db)
    for ev in claim_events(db, batch_size=10, max_attempts=8):
        orch.process_event(db, ev)

    assert db.query(Exposure).count() == 1
    assert db.query(RemediationCase).count() == 1
    assert db.query(CaseExposure).count() == 1


def test_sbom_event_out_of_range_creates_not_affected_without_case(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_occurrence(purl="pkg:pypi/urllib3@9.9.9"))
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "not_affected"
    assert exp.state == "not_affected"
    assert db.query(RemediationCase).count() == 0


def test_sbom_event_kill_switch_creates_exposure_without_case(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_occurrence())
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = _orch(db, settings=_settings(case_auto_create_enabled=False))
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    assert db.query(Exposure).count() == 1
    assert db.query(RemediationCase).count() == 0


def test_sbom_event_osv_failure_leaves_event_undelivered(db):
    from vulnops.workers.orchestration import OutboxOrchestrator, claim_events

    class _BrokenOSV:
        def lookup_batch(self, components, **kwargs):
            raise RuntimeError("network disabled")

    db.add(_occurrence())
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = OutboxOrchestrator(
        session_factory=lambda: db,
        osv=_BrokenOSV(),
        settings=_settings(),
    )
    claimed = claim_events(db, batch_size=10, max_attempts=8)[0]
    with pytest.raises(RuntimeError):
        orch.process_event(db, claimed)
    assert claimed.delivered_at is None
    assert claimed.attempts == 1


def test_run_once_processes_and_marks_batch(db):
    from vulnops.workers.orchestration import claim_events

    db.add(_occurrence())
    db.add(_sbom_event("sbom_1"))
    db.commit()

    orch = _orch(db)
    assert orch.run_once() == 1
    assert all(e.delivered_at is not None for e in claim_events(db, batch_size=10, max_attempts=8))


def test_run_once_stops_after_failure(db):
    from vulnops.workers.orchestration import OutboxOrchestrator

    class _BrokenOSV:
        def lookup_batch(self, components, **kwargs):
            raise RuntimeError("network disabled")

    first = _sbom_event("sbom_1")
    second = _sbom_event("sbom_2")
    second.created_at = first.created_at + timedelta(seconds=1)
    db.add(_occurrence())
    db.add_all([first, second])
    db.commit()

    orch = OutboxOrchestrator(
        session_factory=lambda: db,
        osv=_BrokenOSV(),
        settings=_settings(),
    )
    first_id = first.id
    second_id = second.id
    assert orch.run_once() == 0

    # run_once closes its session, so re-read the rows from a fresh query.
    rows = {e.id: e for e in db.query(OutboxEvent).all()}
    failed = rows[first_id]
    assert failed.attempts == 1  # one attempt, not burned to the cap
    assert failed.delivered_at is None
    # The drain loop stopped claiming: the second event was not processed.
    untouched = rows[second_id]
    assert untouched.attempts == 0
    assert untouched.delivered_at is None


def test_priority_for_flags_kev_enrichment(db):
    class _KevStub:
        def is_kev(self, cve_id: str) -> bool:
            return cve_id == "CVE-2026-KEV"

    orch = _orch(db, osv=_FixtureOSV())
    orch.kev = _KevStub()

    priority, policy_version, kev = orch._priority_for("CVE-2026-KEV", "deterministic", 0.93)
    assert kev is True
    assert priority in ("P0", "P1", "P2", "P3", "P4")
    assert policy_version is not None

    _, _, not_kev = orch._priority_for("CVE-2026-NOT-KEV", "deterministic", 0.93)
    assert not_kev is False


def test_sbom_event_crash_window_does_not_duplicate_case(db):
    # Crash simulation: create_case committed the case row (with its exposures
    # JSON list) but the process died before the CaseExposure link committed.
    # Replaying the SBOM event must not create a second case.
    from vulnops.cases.models import CaseExposure, RemediationCase
    from vulnops.cases.service import CaseService
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events, upsert_exposure

    occ = _occurrence()
    db.add(occ)
    db.commit()

    exposure, _created = upsert_exposure(
        db,
        organization_id="org-demo",
        vulnerability_id="CVE-2026-1234",
        match_class="deterministic",
        confidence=0.93,
        detection_context="sbom:sbom_1",
        component_occurrence_id=occ.id,
        matcher_version="2026.1",
    )
    db.commit()
    CaseService(db).create_case(
        organization_id="org-demo",
        title=f"Remediate CVE-2026-1234 in {occ.normalized_name}",
        owner_team="unassigned",
        priority="P3",
        exposures=[exposure.id],
    )
    # Deliberately no CaseExposure row: the crash lost that write.
    assert db.query(CaseExposure).count() == 0

    db.add(_sbom_event("sbom_1"))
    db.commit()
    orch = _orch(db)
    claimed = claim_events(db, batch_size=10, max_attempts=8)
    sbom_event = next(e for e in claimed if e.event_type == "vulnops.sbom.processed.v1")
    orch.process_event(db, sbom_event)

    assert db.query(Exposure).count() == 1
    assert db.query(RemediationCase).count() == 1


def _dojo_event(**overrides):
    payload = {
        "finding_id": "42",
        "cve": "CVE-2026-1234",
        "purl": "pkg:pypi/urllib3@1.26.17",
        "component_name": "urllib3",
        "component_version": "1.26.17",
        "verified": False,
        "organization_id": "org-demo",
        "mapping": {"status": "matched", "asset_id": None},
        "scan_metadata": {"scope_status": "unknown"},
    }
    payload.update(overrides)
    return _outbox("vulnops.evidence.defectdojo.ingested.v1", payload)


def test_dojo_verified_finding_creates_confirmed_case(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_dojo_event(verified=True))
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "confirmed"
    case = db.query(RemediationCase).one()
    assert case.priority in ("P0", "P1", "P2", "P3")


def test_dojo_unverified_finding_other_purl_has_no_case(db):
    # requests identity is not covered by the urllib3 fixture advisory:
    # identity never matches, so the matcher falls back to candidate.
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(
        _dojo_event(
            purl="pkg:pypi/requests@2.31.0",
            component_name="requests",
            component_version="2.31.0",
        )
    )
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "candidate"
    assert db.query(RemediationCase).count() == 0


def test_dojo_without_purl_is_candidate(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_dojo_event(purl=None, component_version=None))
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "candidate"
    assert exp.component_occurrence_id is None
    assert db.query(RemediationCase).count() == 0


def test_dojo_ambiguous_mapping_skipped(db):
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_dojo_event(mapping={"status": "ambiguous", "asset_id": None}))
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    assert db.query(Exposure).count() == 0


def _wazuh_event(cve="unknown", agent_id="000", org="org-demo"):
    return _outbox(
        "vulnops.evidence.wazuh.ingested.v1",
        {
            "agent_id": agent_id,
            "cve": cve,
            "organization_id": org,
            "package": {"name": "findutils", "version": "4.8.0"},
        },
    )


def test_select_osv_record_for_cve_scans_all_records():
    from types import SimpleNamespace

    from vulnops.workers.orchestration import _select_osv_record_for_cve

    cve = "CVE-2026-8888"
    records = [
        SimpleNamespace(vulnerability_id="GHSA-other", aliases=["GHSA-other"]),
        SimpleNamespace(vulnerability_id=cve, aliases=[cve]),
    ]
    picked = _select_osv_record_for_cve(records, cve)
    assert picked is records[1]
    assert _select_osv_record_for_cve(records[:1], cve) is None


def test_wazuh_unknown_cve_creates_no_exposure(db):
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_wazuh_event())
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    assert db.query(Exposure).count() == 0


def test_wazuh_cve_without_purl_is_candidate(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(_wazuh_event(cve="CVE-2026-9999"))
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "candidate"
    assert exp.state == "candidate"
    assert exp.detection_context == "wazuh:000"
    assert db.query(RemediationCase).count() == 0


def _wazuh_deb_osv_fixture(cve: str, *, fixed: str = "3.0.3") -> dict:
    return {
        "results": [
            {
                "vulns": [
                    {
                        "id": cve,
                        "aliases": [cve],
                        "affected": [
                            {
                                "package": {
                                    "ecosystem": "Debian",
                                    "purl": "pkg:deb/debian/openssl",
                                },
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }


class _WazuhDebOSV:
    def __init__(self, cve: str = "CVE-2026-8888"):
        self.cve = cve

    def lookup_batch(self, components, **kwargs):
        from vulnops.intelligence.osv import OSVAdapter

        return OSVAdapter().lookup_batch(components, raw_fixture=_wazuh_deb_osv_fixture(self.cve))


class _WazuhDebCveMismatchOSV:
    def lookup_batch(self, components, **kwargs):
        from vulnops.intelligence.osv import OSVAdapter

        return OSVAdapter().lookup_batch(
            components,
            raw_fixture={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-unrelated",
                                "aliases": ["GHSA-unrelated"],
                                "affected": [
                                    {
                                        "package": {
                                            "ecosystem": "Debian",
                                            "purl": "pkg:deb/debian/openssl",
                                        },
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "9.9.9"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )


class _WazuhDebMultiVulnOSV:
    """First vuln unrelated; second carries the Wazuh CVE (regression for records[0] bias)."""

    def __init__(self, cve: str = "CVE-2026-8888"):
        self.cve = cve

    def lookup_batch(self, components, **kwargs):
        from vulnops.intelligence.osv import OSVAdapter

        cve = self.cve
        return OSVAdapter().lookup_batch(
            components,
            raw_fixture={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-unrelated",
                                "aliases": ["GHSA-unrelated"],
                                "affected": [
                                    {
                                        "package": {
                                            "ecosystem": "Debian",
                                            "purl": "pkg:deb/debian/openssl",
                                        },
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "9.9.9"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            },
                            {
                                "id": cve,
                                "aliases": [cve],
                                "affected": [
                                    {
                                        "package": {
                                            "ecosystem": "Debian",
                                            "purl": "pkg:deb/debian/openssl",
                                        },
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "3.0.3"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            },
                        ]
                    }
                ]
            },
        )


def test_wazuh_derived_deb_purl_enables_deterministic_match_when_osv_binds_cve(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.intelligence.models import AdvisoryAssertion, AffectedRange
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    cve = "CVE-2026-8888"
    package = {
        "name": "openssl",
        "version": "3.0.2",
        "format": "deb",
        "purl": "pkg:deb/debian/openssl@3.0.2?arch=x86_64",
    }
    db.add(
        _outbox(
            "vulnops.evidence.wazuh.ingested.v1",
            {
                "agent_id": "007",
                "cve": cve,
                "organization_id": "org-demo",
                "package": package,
                "purl_derivation": {"status": "derived", "reason": "deb"},
            },
        )
    )
    db.commit()
    orch = _orch(db, osv=_WazuhDebOSV(cve=cve))
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "deterministic"
    assert exp.state == "active"
    assert db.query(RemediationCase).count() == 1
    assert db.query(AdvisoryAssertion).filter_by(source="osv").count() == 1
    assert db.query(AffectedRange).filter_by(source="osv").count() == 1


def test_wazuh_osv_binds_matching_cve_when_not_first_osv_record(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    cve = "CVE-2026-8888"
    package = {
        "name": "openssl",
        "version": "3.0.2",
        "format": "deb",
        "purl": "pkg:deb/debian/openssl@3.0.2",
    }
    db.add(
        _outbox(
            "vulnops.evidence.wazuh.ingested.v1",
            {
                "agent_id": "007",
                "cve": cve,
                "organization_id": "org-demo",
                "package": package,
                "purl_derivation": {"status": "derived", "reason": "deb"},
            },
        )
    )
    db.commit()
    orch = _orch(db, osv=_WazuhDebMultiVulnOSV(cve=cve))
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "deterministic"
    assert exp.state == "active"
    assert db.query(RemediationCase).count() == 1


def test_wazuh_osv_cve_mismatch_stays_candidate_without_case(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    cve = "CVE-2026-8888"
    package = {
        "name": "openssl",
        "version": "3.0.2",
        "format": "deb",
        "purl": "pkg:deb/debian/openssl@3.0.2",
    }
    db.add(
        _outbox(
            "vulnops.evidence.wazuh.ingested.v1",
            {
                "agent_id": "007",
                "cve": cve,
                "organization_id": "org-demo",
                "package": package,
                "purl_derivation": {"status": "derived", "reason": "deb"},
            },
        )
    )
    db.commit()
    orch = _orch(db, osv=_WazuhDebCveMismatchOSV())
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "candidate"
    assert "osv lookup did not confirm the Wazuh CVE" in " ".join(exp.limitations or [])
    assert db.query(RemediationCase).count() == 0


def test_wazuh_skipped_purl_derivation_stays_candidate(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    db.add(
        _outbox(
            "vulnops.evidence.wazuh.ingested.v1",
            {
                "agent_id": "008",
                "cve": "CVE-2026-7777",
                "organization_id": "org-demo",
                "package": {"name": "openssl", "version": "3.0.2", "format": "deb"},
                "purl_derivation": {"status": "skipped", "reason": "deb_distro_unknown"},
            },
        )
    )
    db.commit()
    orch = _orch(db)
    ev = claim_events(db, batch_size=10, max_attempts=8)[0]
    orch.process_event(db, ev)

    exp = db.query(Exposure).one()
    assert exp.match_class == "candidate"
    assert db.query(RemediationCase).count() == 0


def test_dojo_verified_finding_with_jira_key_links_ticket(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.db.models.audit_event import AuditEvent
    from vulnops.workers.orchestration import claim_events

    payload = {
        "finding_id": "77",
        "cve": "CVE-2026-1234",
        "purl": "pkg:pypi/urllib3@1.26.17",
        "component_name": "urllib3",
        "component_version": "1.26.17",
        "verified": True,
        "jira_key": "VULN-42",
        "organization_id": "org-demo",
        "mapping": {"status": "matched", "asset_id": None},
        "scan_metadata": {"scope_status": "unknown"},
    }
    db.add(_outbox("vulnops.evidence.defectdojo.ingested.v1", payload))
    db.commit()
    orch = _orch(db)
    ev = next(
        e
        for e in claim_events(db, batch_size=10, max_attempts=8)
        if e.event_type == "vulnops.evidence.defectdojo.ingested.v1"
    )
    orch.process_event(db, ev)

    case = db.query(RemediationCase).one()
    assert case.external_ticket_id == "VULN-42"
    link = db.query(AuditEvent).filter_by(action="case.external_ticket.linked").one()
    assert link.reason == "jira via defectdojo finding 77"


def test_dojo_greenbone_provenance_keeps_scanner_confirmed_case_path(db):
    from vulnops.cases.models import RemediationCase
    from vulnops.db.models.audit_event import AuditEvent
    from vulnops.matching.models import Exposure
    from vulnops.workers.orchestration import claim_events

    payload = {
        "finding_id": "123456",
        "cve": "CVE-2026-1234",
        "purl": "pkg:pypi/urllib3@1.26.17",
        "component_name": "urllib3",
        "component_version": "1.26.17",
        "verified": True,
        "jira_key": "VULN-99",
        "scanner": "Greenbone/OpenVAS",
        "scan_type": "OpenVAS Scan",
        "organization_id": "org-demo",
        "mapping": {"status": "matched", "asset_id": None},
        "scan_metadata": {
            "scanner": "Greenbone/OpenVAS",
            "scan_type": "OpenVAS Scan",
            "test_type": "OpenVAS Scan",
        },
    }
    event = _outbox("vulnops.evidence.defectdojo.ingested.v1", payload)
    db.add(event)
    db.commit()

    orch = _orch(db)
    claimed = claim_events(db, batch_size=10, max_attempts=8)
    orch.process_event(db, claimed[0])

    exposure = db.query(Exposure).one()
    assert exposure.match_class == "confirmed"
    assert "scanner.confirmed" in exposure.matched_rules
    case = db.query(RemediationCase).one()
    assert case.external_ticket_id == "VULN-99"
    link = db.query(AuditEvent).filter_by(action="case.external_ticket.linked").one()
    assert link.reason == "jira via defectdojo finding 123456"
    assert event.payload["scanner"] == "Greenbone/OpenVAS"
    assert event.payload["scan_metadata"]["scan_type"] == "OpenVAS Scan"

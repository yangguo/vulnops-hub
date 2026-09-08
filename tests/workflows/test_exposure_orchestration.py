"""Orchestration worker tests: outbox events -> exposures -> auto cases."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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
    fail_event(db, ev)
    assert ev.attempts == 1


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

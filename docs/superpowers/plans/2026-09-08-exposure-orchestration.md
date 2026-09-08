# Exposure Generation Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the outbox-polling orchestrator that turns ingested evidence into exposures and (for deterministic matches) auto-created remediation cases.

**Architecture:** A new worker module polls `outbox_events` (`delivered_at IS NULL`), dispatches per event type to handlers that query OSV for advisories, run `MatchingService.evaluate`, upsert `Exposure` rows on their natural key, and auto-create cases via `CaseService` when policy allows. Each handler commits its own transaction; the outbox row is marked `delivered_at` only after success; failures increment `attempts` with backoff.

**Tech Stack:** Python 3.12, SQLAlchemy (SQLite in tests, Postgres in deployment), httpx (via existing injectable adapters), pytest.

**Spec:** `docs/superpowers/specs/2026-09-08-exposure-orchestration-design.md`

## Global Constraints

- Python 3.12; match the repo's ruff style — run `uv run ruff check src tests` and `uv run ruff format --check src tests` before each commit (enforced as a step in Task 7; keep files clean as you go).
- Tests never hit the network: use the adapters' `raw_fixture` / `http_client` injection seams.
- The adapter rule holds: evidence bridges never create cases — only this orchestrator does.
- Test DB pattern used by the existing suite: `create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})` + `Base.metadata.create_all` + `sessionmaker`.
- All timestamps UTC (`datetime.now(UTC)`); id prefixes `exp_`, `mev_`, `cx_`.
- Commit after every green step: `feat:`/`fix:`/`test:`/`docs:` prefixes.

---

### Task 1: Orchestrator settings + test scaffolding

**Files:**
- Modify: `src/vulnops/config.py` (append fields to `Settings`, after `wazuh_base_url` ~line 111)
- Create: `tests/workflows/test_exposure_orchestration.py`

**Interfaces:**
- Produces: `Settings` fields `orchestrator_poll_interval_seconds: float = 5.0`, `orchestrator_batch_size: int = 50`, `orchestrator_max_attempts: int = 8`, `case_auto_create_enabled: bool = True`, `default_case_owner_team: str = "unassigned"`.
- Produces (test scaffolding reused by every later task): the `db` fixture, `_outbox()` and `_settings()` helpers, and module imports.

- [ ] **Step 1: Create the test file with scaffolding + failing settings test**

`tests/workflows/test_exposure_orchestration.py`:

```python
"""Orchestration worker tests: outbox events -> exposures -> auto cases."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.config import Settings
from vulnops.db import Base


def _settings(**overrides) -> Settings:
    """Settings instance safe for unit tests (no test bypass needed here)."""

    defaults = dict(oidc_issuer_url="http://127.0.0.1:8082/realms/vulnops", oidc_audience="vulnops-api")
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


def _outbox(event_type: str, payload: dict) -> "OutboxEvent":
    from vulnops.db.models.outbox_event import OutboxEvent

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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: FAIL — pydantic validation error (`orchestrator_poll_interval_seconds` does not match any field / extra ignored so assertion fails on missing attribute).

- [ ] **Step 3: Add the settings fields**

In `src/vulnops/config.py`, after the `wazuh_base_url` field:

```python
    # Orchestration
    orchestrator_poll_interval_seconds: float = Field(default=5.0)
    orchestrator_batch_size: int = Field(default=50)
    orchestrator_max_attempts: int = Field(default=8)
    case_auto_create_enabled: bool = Field(default=True)
    default_case_owner_team: str = Field(default="unassigned")
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vulnops/config.py tests/workflows/test_exposure_orchestration.py
git commit -m "feat(orchestration): add worker and case-creation settings"
```

---

### Task 2: Outbox claim/complete/fail + exposure upsert

**Files:**
- Create: `src/vulnops/workers/orchestration.py`
- Modify: `tests/workflows/test_exposure_orchestration.py` (append)

**Interfaces:**
- Consumes: `OutboxEvent` (`src/vulnops/db/models/outbox_event.py` — `id`, `event_type`, `payload`, `delivered_at`, `attempts`, `created_at`); `Exposure` / `MatchEvidence` (`src/vulnops/matching/models.py`).
- Produces:
  - `claim_events(session, batch_size: int, max_attempts: int) -> list[OutboxEvent]` — undelivered rows with `attempts < max_attempts`, oldest first, `with_for_update(skip_locked=True)` (no-op on SQLite, effective on Postgres).
  - `complete_event(session, event) -> None` — sets `delivered_at`, commits.
  - `fail_event(session, event) -> None` — rolls back the handler's partial transaction, re-reads the row, increments `attempts`, commits.
  - `upsert_exposure(session, *, organization_id, vulnerability_id, match_class, confidence, detection_context, component_occurrence_id=None, asset_id=None, matched_rules=None, evidence_refs=None, limitations=None, matcher_version=None, priority=None, policy_version=None, evidence_ref=None) -> tuple[Exposure, bool]` — dedup key `(organization_id, vulnerability_id, detection_context, component_occurrence_id)` with `detection_context` never None; on replay updates `last_observed_at`/`match_class`/`confidence`/`state`/`priority` and appends `MatchEvidence` only for unseen `evidence_ref`. Returns `(exposure, created)`. State mapping: `not_affected` → `not_affected`; `confirmed`/`deterministic` → `active`; everything else → `candidate`.

- [ ] **Step 1: Write failing tests**

Append to `tests/workflows/test_exposure_orchestration.py`:

```python
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
    from vulnops.workers.orchestration import claim_events, complete_event

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
    from vulnops.matching.models import Exposure
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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'vulnops.workers.orchestration'`

- [ ] **Step 3: Implement the module**

Create `src/vulnops/workers/orchestration.py`:

```python
"""Outbox orchestration: evidence events -> exposures -> (policy-gated) cases.

Consumes undelivered rows from outbox_events, dispatches by event_type to a
handler that queries intelligence for advisories, evaluates matches, and
upserts exposures. Deterministic/confirmed matches create remediation cases
through CaseService when CASE_AUTO_CREATE_ENABLED. Each handler commits its
own transaction; the outbox row is marked delivered only after success.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.matching.models import Exposure, MatchEvidence

logger = logging.getLogger("vulnops.workers.orchestration")

_CASE_CLASSES = ("confirmed", "deterministic")


def claim_events(session: Session, batch_size: int, max_attempts: int) -> list[OutboxEvent]:
    """Return undelivered outbox rows under the attempt cap, oldest first."""

    rows = (
        session.query(OutboxEvent)
        .filter(OutboxEvent.delivered_at.is_(None), OutboxEvent.attempts < max_attempts)
        .order_by(OutboxEvent.created_at)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .all()
    )
    return list(rows)


def complete_event(session: Session, event: OutboxEvent) -> None:
    event.delivered_at = datetime.now(UTC)
    session.commit()


def fail_event(session: Session, event: OutboxEvent) -> None:
    session.rollback()
    stored = session.get(OutboxEvent, event.id)
    stored.attempts = (stored.attempts or 0) + 1
    session.commit()


def upsert_exposure(session: Session, **kwargs: Any) -> tuple[Exposure, bool]:
    """Idempotently create or refresh one exposure keyed by org+vuln+context."""

    organization_id = kwargs["organization_id"]
    vulnerability_id = kwargs["vulnerability_id"]
    detection_context = kwargs["detection_context"]
    component_occurrence_id = kwargs.get("component_occurrence_id")

    query = session.query(Exposure).filter(
        Exposure.organization_id == organization_id,
        Exposure.vulnerability_id == vulnerability_id,
        Exposure.detection_context == detection_context,
    )
    if component_occurrence_id is None:
        query = query.filter(Exposure.component_occurrence_id.is_(None))
    else:
        query = query.filter(Exposure.component_occurrence_id == component_occurrence_id)
    existing = query.first()

    match_class = kwargs["match_class"]
    state = (
        "not_affected"
        if match_class == "not_affected"
        else ("active" if match_class in _CASE_CLASSES else "candidate")
    )

    if existing is not None:
        existing.last_observed_at = datetime.now(UTC)
        existing.match_class = match_class
        existing.confidence = kwargs["confidence"]
        existing.state = state
        if kwargs.get("matched_rules"):
            existing.matched_rules = kwargs["matched_rules"]
        if kwargs.get("priority"):
            existing.priority = kwargs["priority"]
        if kwargs.get("policy_version"):
            existing.policy_version = kwargs["policy_version"]
        exposure = existing
        created = False
    else:
        exposure = Exposure(
            id=f"exp_{uuid.uuid4().hex[:12]}",
            organization_id=organization_id,
            component_occurrence_id=component_occurrence_id,
            asset_id=kwargs.get("asset_id"),
            vulnerability_id=vulnerability_id,
            detection_context=detection_context,
            match_class=match_class,
            confidence=kwargs["confidence"],
            state=state,
            matched_rules=kwargs.get("matched_rules"),
            evidence_refs=kwargs.get("evidence_refs"),
            limitations=kwargs.get("limitations"),
            matcher_version=kwargs.get("matcher_version"),
            priority=kwargs.get("priority"),
            policy_version=kwargs.get("policy_version"),
        )
        session.add(exposure)
        session.flush()
        created = True

    evidence_ref = kwargs.get("evidence_ref")
    if evidence_ref:
        seen = (
            session.query(MatchEvidence)
            .filter(
                MatchEvidence.exposure_id == exposure.id,
                MatchEvidence.evidence_ref == evidence_ref,
            )
            .first()
        )
        if seen is None:
            session.add(
                MatchEvidence(
                    id=f"mev_{uuid.uuid4().hex[:12]}",
                    exposure_id=exposure.id,
                    vulnerability_id=vulnerability_id,
                    evidence_ref=evidence_ref,
                    matcher_version=kwargs.get("matcher_version"),
                )
            )
    return exposure, created
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/vulnops/workers/orchestration.py tests/workflows/test_exposure_orchestration.py
git commit -m "feat(orchestration): add outbox claim and exposure upsert helpers"
```

---

### Task 3: OSV records carry their component query index

**Files:**
- Modify: `src/vulnops/intelligence/osv.py` (the `AdvisoryRecord(...)` construction in `lookup_batch`, ~line 140)
- Modify: `tests/workflows/test_exposure_orchestration.py` (append)

**Interfaces:**
- Produces: every `AdvisoryRecord` from `lookup_batch` carries `retrieval_metadata["query_index"] = idx` (index into the `components` argument; OSV's `results` array aligns with `queries`). Task 4 groups records by this index.

- [ ] **Step 1: Write failing tests**

Append:

```python
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
        OSVAdapter(http_client=_NeverClient()).lookup_batch([{"purl": "pkg:pypi/a", "version": "1"}])
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -k query_index -v`
Expected: FAIL — `KeyError: 'query_index'`

- [ ] **Step 3: Implement**

In `src/vulnops/intelligence/osv.py`, the `AdvisoryRecord(...)` construction inside `lookup_batch` becomes:

```python
                rec = AdvisoryRecord(
                    vulnerability_id=vuln_id,
                    source=self.source,
                    retrieved_at=now,
                    source_url=url,
                    content=vuln,
                    description=vuln.get("summary") or vuln.get("details"),
                    aliases=vuln.get("aliases", []),
                    affected_ranges=affected,
                    references=[r.get("url") for r in vuln.get("references", []) if r.get("url")],
                    retrieval_metadata={"query_index": idx},
                )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add src/vulnops/intelligence/osv.py tests/workflows/test_exposure_orchestration.py
git commit -m "feat(intelligence): tag OSV records with component query index"
```

---

### Task 4: Orchestrator class — SBOM handler, priority, auto-case

**Files:**
- Modify: `src/vulnops/workers/orchestration.py` (append)
- Modify: `tests/workflows/test_exposure_orchestration.py` (append)

**Interfaces:**
- Consumes: Task 2 helpers; `OSVAdapter.lookup_batch` with Task 3's `query_index`; `MatchingService.evaluate(component, advisory, asset_context=None, scanner_evidence=None, vex_status=None) -> ExposureResult` (`match_class`, `confidence`, `should_create_case`, `matched_rules`, `limitations`, `matcher_version`); `RiskPolicyEngine.evaluate(PolicyInput) -> PolicyResult` (`priority`, `policy_version`); `CaseService.create_case(organization_id, title, owner_team, priority="P2", exposures=None, policy_version=None, assignee=None) -> RemediationCase` (commits internally, creates SLA clock + audit + outbox); `CaseExposure` (`src/vulnops/cases/models.py`: `case_id`, `exposure_id`); `ComponentOccurrence` (`src/vulnops/sbom/models.py`: `sbom_id`, `purl`, `raw_name`, `raw_version`, `asset_id`, `ecosystem`, `normalized_name`, `version_scheme`); `ParsedComponent` (`src/vulnops/sbom/parser.py`).
- Produces:
  - `_advisory_from_record(record) -> dict` — converts `AdvisoryRecord.affected_ranges` (`[{ecosystem, purl, type, introduced, fixed}]`) into the matcher's OSV shape: `{"id": record.vulnerability_id, "affected": [{"package": {"ecosystem", "purl"}, "ranges": [{"type", "events": [{"introduced"}, {"fixed"}]}]}]}`.
  - `_component_from_occurrence(occurrence) -> ParsedComponent`.
  - `OutboxOrchestrator(session_factory, osv=None, kev=None, epss=None, settings=None)` — `osv` defaults to `OSVAdapter()`; `settings` defaults to `get_settings()`.
  - `process_event(session, event) -> str | None` — dispatch by `event_type`; unknown types are marked delivered with a warning and return None. Handler exceptions call `fail_event` and re-raise.
  - `run_once() -> int` — claims a batch and processes each event; returns delivered count.
  - `run_forever(max_iterations=None)` — polls with `settings.orchestrator_poll_interval_seconds`.
  - `_priority_for(vulnerability_id, match_class, confidence) -> tuple[str, str, bool]` — `(priority, policy_version, kev)`; KEV via injected `kev.is_kev`, EPSS via injected `epss.get_scores([cve])` (best-effort: failures degrade to no enrichment with a warning, never block matching).
  - `_maybe_create_case(session, exposure, component_label) -> RemediationCase | None` — only when `settings.case_auto_create_enabled`, `match_class in ("confirmed", "deterministic")`, and no non-closed case already links the exposure; creates the case via `CaseService` (priority falls back to `exposure.priority` then `"P2"`), then adds a `CaseExposure` row and commits.

- [ ] **Step 1: Write failing tests**

Append to `tests/workflows/test_exposure_orchestration.py`:

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: FAIL — `ImportError: cannot import name 'OutboxOrchestrator'`

- [ ] **Step 3: Implement**

Append to `src/vulnops/workers/orchestration.py`. First extend the import block to exactly:

```python
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from vulnops.cases.models import CaseExposure, CaseStatus, RemediationCase
from vulnops.cases.service import CaseService
from vulnops.config import get_settings
from vulnops.db.models.outbox_event import OutboxEvent
from vulnops.intelligence.osv import OSVAdapter
from vulnops.matching.models import Exposure, MatchEvidence
from vulnops.matching.service import MatchingService
from vulnops.risk.policy import PolicyInput, RiskPolicyEngine
from vulnops.sbom.models import ComponentOccurrence
from vulnops.sbom.parser import ParsedComponent
```

Then append the helpers and the class:

```python
def _advisory_from_record(record: Any) -> dict[str, Any]:
    """Convert an AdvisoryRecord's affected_ranges into matcher OSV shape."""

    affected: list[dict[str, Any]] = []
    for rng in record.affected_ranges or []:
        events: list[dict[str, str]] = []
        if rng.get("introduced"):
            events.append({"introduced": rng["introduced"]})
        if rng.get("fixed"):
            events.append({"fixed": rng["fixed"]})
        if not events:
            continue
        affected.append(
            {
                "package": {"ecosystem": rng.get("ecosystem"), "purl": rng.get("purl")},
                "ranges": [{"type": rng.get("type") or "ECOSYSTEM", "events": events}],
            }
        )
    return {"id": record.vulnerability_id, "affected": affected}


def _component_from_occurrence(occurrence: Any) -> ParsedComponent:
    return ParsedComponent(
        raw_name=occurrence.raw_name,
        raw_version=occurrence.raw_version,
        purl=occurrence.purl,
        ecosystem=occurrence.ecosystem,
        normalized_name=occurrence.normalized_name,
        cpe=occurrence.cpe,
        version_scheme=occurrence.version_scheme,
    )


class OutboxOrchestrator:
    """Consume evidence outbox events and materialize exposures/cases."""

    def __init__(self, session_factory, osv=None, kev=None, epss=None, settings=None):
        self.session_factory = session_factory
        self.osv = osv or OSVAdapter()
        self.kev = kev
        self.epss = epss
        self.settings = settings or get_settings()
        self.matcher = MatchingService()
        self.policy = RiskPolicyEngine()

    # -- dispatch ----------------------------------------------------------

    _HANDLERS: dict[str, str] = {
        "vulnops.sbom.processed.v1": "_handle_sbom_processed",
    }

    def process_event(self, session: Session, event: OutboxEvent) -> str | None:
        name = self._HANDLERS.get(event.event_type)
        if name is None:
            logger.warning("no handler for event_type=%s; marking delivered", event.event_type)
            complete_event(session, event)
            return None
        handler: Any = getattr(self, name)
        try:
            summary = handler(session, event)
        except Exception:
            fail_event(session, event)
            raise
        complete_event(session, event)
        return summary

    def run_once(self) -> int:
        session = self.session_factory()
        try:
            events = claim_events(
                session,
                batch_size=self.settings.orchestrator_batch_size,
                max_attempts=self.settings.orchestrator_max_attempts,
            )
            delivered = 0
            for event in events:
                self.process_event(session, event)
                delivered += 1
            return delivered
        finally:
            session.close()

    def run_forever(self, max_iterations: int | None = None) -> None:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            iterations += 1
            try:
                count = self.run_once()
                if count:
                    logger.info("orchestrator delivered %d event(s)", count)
            except Exception:
                logger.exception("orchestrator loop error; backing off")
            time.sleep(self.settings.orchestrator_poll_interval_seconds)

    # -- priority ----------------------------------------------------------

    def _priority_for(self, vulnerability_id: str, match_class: str, confidence: float):
        kev = bool(self.kev is not None and self.kev.is_kev(vulnerability_id))
        epss_score = 0.0
        epss_percentile = None
        if self.epss is not None:
            try:
                rec = self.epss.get_scores([vulnerability_id]).get(vulnerability_id)
                if rec is not None:
                    epss_score = float(rec.epss_score or 0.0)
                    epss_percentile = rec.epss_percentile
            except Exception as exc:  # enrichment is best-effort, never blocking
                logger.warning("EPSS lookup failed for %s: %s", vulnerability_id, exc)
        result = self.policy.evaluate(
            PolicyInput(
                vulnerability_id=vulnerability_id,
                kev=kev,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                match_confidence=confidence,
                match_class=match_class,
            )
        )
        return result.priority, result.policy_version, kev

    # -- case creation -----------------------------------------------------

    def _maybe_create_case(self, session: Session, exposure: Exposure, component_label: str):
        if not self.settings.case_auto_create_enabled:
            return None
        if exposure.match_class not in _CASE_CLASSES:
            return None
        existing = (
            session.query(RemediationCase)
            .join(CaseExposure, CaseExposure.case_id == RemediationCase.id)
            .filter(
                CaseExposure.exposure_id == exposure.id,
                RemediationCase.status != CaseStatus.CLOSED,
            )
            .first()
        )
        if existing is not None:
            return None
        case = CaseService(session).create_case(
            organization_id=exposure.organization_id,
            title=f"Remediate {exposure.vulnerability_id} in {component_label}",
            owner_team=self.settings.default_case_owner_team,
            priority=exposure.priority or "P2",
            exposures=[exposure.id],
            policy_version=exposure.policy_version,
        )
        session.add(
            CaseExposure(id=f"cx_{uuid.uuid4().hex[:12]}", case_id=case.id, exposure_id=exposure.id)
        )
        session.commit()
        return case

    # -- handlers ----------------------------------------------------------

    def _handle_sbom_processed(self, session: Session, event: OutboxEvent) -> str:
        payload = event.payload or {}
        sbom_id = payload["sbom_id"]
        organization_id = payload.get("organization_id") or "default"

        occurrences = session.query(ComponentOccurrence).filter_by(sbom_id=sbom_id).all()
        ordered = [o for o in occurrences if o.purl and o.raw_version]
        query_components = [{"purl": o.purl, "version": o.raw_version} for o in ordered]
        records = self.osv.lookup_batch(query_components) if query_components else []

        by_index: dict[int, list[Any]] = {}
        for rec in records:
            by_index.setdefault(rec.retrieval_metadata.get("query_index", -1), []).append(rec)

        exposure_count = 0
        for idx, occurrence in enumerate(ordered):
            for rec in by_index.get(idx, []):
                advisory = _advisory_from_record(rec)
                component = _component_from_occurrence(occurrence)
                result = self.matcher.evaluate(component, advisory)
                priority, policy_version, _kev = self._priority_for(
                    rec.vulnerability_id, result.match_class, result.confidence
                )
                exposure, _created = upsert_exposure(
                    session,
                    organization_id=organization_id,
                    vulnerability_id=rec.vulnerability_id,
                    match_class=result.match_class,
                    confidence=result.confidence,
                    detection_context=f"sbom:{sbom_id}",
                    component_occurrence_id=occurrence.id,
                    asset_id=occurrence.asset_id,
                    matched_rules=result.matched_rules,
                    evidence_refs=[event.id],
                    limitations=result.limitations,
                    matcher_version=result.matcher_version,
                    priority=priority,
                    policy_version=policy_version,
                    evidence_ref=event.id,
                )
                session.commit()
                self._maybe_create_case(
                    session, exposure, occurrence.normalized_name or occurrence.raw_name
                )
                exposure_count += 1
        return f"sbom={sbom_id} exposures={exposure_count}"
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: PASS (16 tests)

- [ ] **Step 5: Commit**

```bash
git add src/vulnops/workers/orchestration.py tests/workflows/test_exposure_orchestration.py
git commit -m "feat(orchestration): sbom events produce exposures and auto cases"
```

---

### Task 5: DefectDojo handler

**Files:**
- Modify: `src/vulnops/integrations/defectdojo.py` (outbox payload dict, ~line 215)
- Modify: `src/vulnops/workers/orchestration.py` (dispatch entry + handler + helper)
- Modify: `tests/workflows/test_exposure_orchestration.py` (append)

**Interfaces:**
- Consumes: Task 4's helpers; the enriched bridge payload `{"finding_id", "cve", "purl", "component_name", "component_version", "verified", "organization_id", "mapping": {"status", "asset_id"}, "scan_metadata"}`.
- Produces: `_handle_defectdojo_ingested(session, event) -> str`. Semantics: ambiguous mapping → skip (no exposure, event still delivered); no CVE → skip; purl present → OSV lookup for the real advisory, `verified=true` passes `scanner_evidence={"scanner_confirmed": True, "finding_id": ...}` into the matcher (its `confirmed` short-circuit); no purl → `candidate` exposure only. `_component_from_fields(raw_name, raw_version, purl) -> ParsedComponent` derives the ecosystem from the purl prefix.

- [ ] **Step 1: Enrich the bridge payload**

In `src/vulnops/integrations/defectdojo.py`, replace the outbox payload dict (~line 215) with:

```python
                payload={
                    "finding_id": finding_id,
                    "cve": cve,
                    "purl": purl,
                    "component_name": component_name,
                    "component_version": component_version,
                    "verified": bool(raw.get("verified")),
                    "organization_id": organization_id,
                    "mapping": {"status": mapping.status, "asset_id": mapping.asset_id},
                    "scan_metadata": scan_metadata,
                },
```

- [ ] **Step 2: Write failing tests**

Append:

```python
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
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -k dojo -v`
Expected: FAIL — exposures count 0 (no handler registered; events marked delivered as unknown)

- [ ] **Step 4: Implement**

Extend `_HANDLERS` in `src/vulnops/workers/orchestration.py`:

```python
    _HANDLERS: dict[str, str] = {
        "vulnops.sbom.processed.v1": "_handle_sbom_processed",
        "vulnops.evidence.defectdojo.ingested.v1": "_handle_defectdojo_ingested",
    }
```

Add the module-level helper next to `_component_from_occurrence`:

```python
def _component_from_fields(*, raw_name: str, raw_version: str | None, purl: str | None) -> ParsedComponent:
    ecosystem = None
    if purl and purl.startswith("pkg:"):
        ecosystem = purl[4:].split("/")[0].lower()
    return ParsedComponent(
        raw_name=raw_name,
        raw_version=raw_version,
        purl=purl,
        ecosystem=ecosystem,
        normalized_name=raw_name,
        cpe=None,
        version_scheme=ecosystem,
    )
```

Append the method to `OutboxOrchestrator`:

```python
    def _handle_defectdojo_ingested(self, session: Session, event: OutboxEvent) -> str:
        payload = event.payload or {}
        finding_id = str(payload.get("finding_id"))
        mapping_status = (payload.get("mapping") or {}).get("status")
        if mapping_status == "ambiguous":
            return f"dojo={finding_id} skipped-ambiguous"

        cve = payload.get("cve")
        if not cve or cve == "unknown":
            return f"dojo={finding_id} skipped-no-cve"

        organization_id = payload.get("organization_id") or "default"
        purl = payload.get("purl")
        component_name = payload.get("component_name") or "unknown"
        component_version = payload.get("component_version")
        verified = bool(payload.get("verified"))

        advisory: dict[str, Any] = {"id": cve, "affected": []}
        if purl:
            records = self.osv.lookup_batch([{"purl": purl, "version": component_version}])
            if records:
                advisory = _advisory_from_record(records[0])
                advisory["id"] = advisory.get("id") or cve

        component = _component_from_fields(
            raw_name=component_name, raw_version=component_version, purl=purl
        )
        scanner_evidence = (
            {"scanner_confirmed": True, "finding_id": finding_id} if verified else None
        )
        result = self.matcher.evaluate(component, advisory, scanner_evidence=scanner_evidence)
        priority, policy_version, _kev = self._priority_for(cve, result.match_class, result.confidence)
        exposure, _created = upsert_exposure(
            session,
            organization_id=organization_id,
            vulnerability_id=cve,
            match_class=result.match_class,
            confidence=result.confidence,
            detection_context=f"defectdojo:{finding_id}",
            component_occurrence_id=None,
            asset_id=(payload.get("mapping") or {}).get("asset_id"),
            matched_rules=result.matched_rules,
            evidence_refs=[event.id],
            limitations=result.limitations,
            matcher_version=result.matcher_version,
            priority=priority,
            policy_version=policy_version,
            evidence_ref=event.id,
        )
        session.commit()
        if purl:
            self._maybe_create_case(session, exposure, component_name)
        return f"dojo={finding_id} match={result.match_class}"
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: PASS (20 tests)

- [ ] **Step 6: Commit**

```bash
git add src/vulnops/integrations/defectdojo.py src/vulnops/workers/orchestration.py tests/workflows/test_exposure_orchestration.py
git commit -m "feat(orchestration): defectdojo evidence events produce exposures"
```

---

### Task 6: Wazuh handler

**Files:**
- Modify: `src/vulnops/integrations/wazuh.py` (add `organization_id` to the outbox payload, same pattern as Task 5 Step 1)
- Modify: `src/vulnops/workers/orchestration.py` (dispatch entry + handler)
- Modify: `tests/workflows/test_exposure_orchestration.py` (append)

**Interfaces:**
- Consumes: outbox payload `{"agent_id", "cve", "package": {...}, "organization_id"}` — the live payload (verified against staging DB) carries no purl.
- Produces: `_handle_wazuh_ingested(session, event) -> str`. `cve` missing or `"unknown"` → no exposure (snapshot evidence already retained). Real CVE without purl → one `candidate` exposure with `detection_context=f"wazuh:{agent_id}"`. Never creates a case.

- [ ] **Step 1: Enrich the bridge payload**

In `src/vulnops/integrations/wazuh.py`, the outbox payload dict (~line 119) becomes:

```python
                payload={
                    "agent_id": agent_id,
                    "cve": cve,
                    "package": package,
                    "organization_id": organization_id,
                    "mapping": {"status": mapping.status, "asset_id": mapping.asset_id},
                    "scan_metadata": scan_metadata,
                },
```

- [ ] **Step 2: Write failing tests**

Append:

```python
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
```

- [ ] **Step 3: Run to verify failure**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -k wazuh -v`
Expected: FAIL — exposures count 0 (no handler)

- [ ] **Step 4: Implement**

Extend `_HANDLERS`:

```python
    _HANDLERS: dict[str, str] = {
        "vulnops.sbom.processed.v1": "_handle_sbom_processed",
        "vulnops.evidence.defectdojo.ingested.v1": "_handle_defectdojo_ingested",
        "vulnops.evidence.wazuh.ingested.v1": "_handle_wazuh_ingested",
    }
```

Append the method:

```python
    def _handle_wazuh_ingested(self, session: Session, event: OutboxEvent) -> str:
        payload = event.payload or {}
        agent_id = str(payload.get("agent_id") or "unknown")
        cve = payload.get("cve")
        if not cve or cve == "unknown":
            return f"wazuh={agent_id} no-cve"
        organization_id = payload.get("organization_id") or "default"
        exposure, _created = upsert_exposure(
            session,
            organization_id=organization_id,
            vulnerability_id=cve,
            match_class="candidate",
            confidence=0.35,
            detection_context=f"wazuh:{agent_id}",
            component_occurrence_id=None,
            matched_rules=["wazuh.package-candidate"],
            evidence_refs=[event.id],
            limitations=["package inventory without purl; review required"],
            matcher_version="2026.1",
            evidence_ref=event.id,
        )
        session.commit()
        return f"wazuh={agent_id} match=candidate exposure={exposure.id}"
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -v`
Expected: PASS (22 tests)

- [ ] **Step 6: Commit**

```bash
git add src/vulnops/integrations/wazuh.py src/vulnops/workers/orchestration.py tests/workflows/test_exposure_orchestration.py
git commit -m "feat(orchestration): wazuh cve events create candidate exposures"
```

---

### Task 7: Entrypoint, compose service, full suite + lint

**Files:**
- Modify: `src/vulnops/workers/orchestration.py` (append `main()`)
- Modify: `docker-compose.yml` (add `orchestrator` service after `worker`)

**Interfaces:**
- Produces: `python -m vulnops.workers.orchestration` entrypoint; `orchestrator` container with the same env contract as `worker` plus the new settings passthrough.

- [ ] **Step 1: Add the entrypoint**

Append to `src/vulnops/workers/orchestration.py`:

```python
def main() -> None:
    logging.basicConfig(level=logging.INFO)
    from vulnops.db import get_engine, get_sessionmaker
    from vulnops.intelligence.epss import EPSSAdapter
    from vulnops.intelligence.kev import KEVAdapter

    settings = get_settings()
    engine = get_engine()
    kev = KEVAdapter()
    try:
        kev.fetch_catalog()
        logger.info("KEV catalog loaded")
    except Exception as exc:
        logger.warning("KEV catalog unavailable at startup: %s", exc)

    orchestrator = OutboxOrchestrator(
        session_factory=lambda: get_sessionmaker(engine)(),
        kev=kev,
        epss=EPSSAdapter(),
        settings=settings,
    )
    orchestrator.run_forever()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Add the compose service**

In `docker-compose.yml`, after the `worker` service:

```yaml
  orchestrator:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      ENVIRONMENT: ${ENVIRONMENT:-development}
      DATABASE_URL: postgresql+psycopg2://vulnops:vulnops@postgres:5432/vulnops
      REDIS_URL: redis://valkey:6379/0
      OBJECT_STORAGE_ENDPOINT: http://minio:9000
      OBJECT_STORAGE_BUCKET: vulnops-snapshots
      OBJECT_STORAGE_ACCESS_KEY: minioadmin
      OBJECT_STORAGE_SECRET_KEY: minioadmin
      OIDC_ISSUER_URL: ${OIDC_ISSUER_URL:-}
      OIDC_AUDIENCE: ${OIDC_AUDIENCE:-}
      CASE_AUTO_CREATE_ENABLED: ${CASE_AUTO_CREATE_ENABLED:-true}
      DEFAULT_CASE_OWNER_TEAM: ${DEFAULT_CASE_OWNER_TEAM:-unassigned}
      ORCHESTRATOR_POLL_INTERVAL_SECONDS: ${ORCHESTRATOR_POLL_INTERVAL_SECONDS:-5}
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
      minio:
        condition: service_healthy
    command: python -m vulnops.workers.orchestration
    restart: unless-stopped
```

- [ ] **Step 3: Full suite + lint**

Run: `uv run pytest && uv run ruff check src tests && uv run ruff format --check src tests`
Expected: all green; fix findings before committing.

- [ ] **Step 4: Commit**

```bash
git add src/vulnops/workers/orchestration.py docker-compose.yml
git commit -m "feat(orchestration): add worker entrypoint and compose service"
```

---

### Task 8: Staging closed-loop verification and evidence

**Files:**
- Modify: `docs/operations/integrated-staging.md` (evidence log row)
- Modify: `docs/acceptance-matrix.md` (exposure row update)

- [ ] **Step 1: Bring the environment up**

```bash
docker compose up -d postgres valkey minio
docker compose -f deploy/docker-compose.staging.yml --env-file deploy/.env.staging \
  --profile keycloak --profile defectdojo up -d
```

Host processes (Docker `api`/`worker`/`orchestrator` stay stopped to avoid double consumers):

```bash
SSL_CERT_FILE=/d/dev-cache/kaspersky-ca.pem uv run uvicorn vulnops.main:app --port 8000
SSL_CERT_FILE=/d/dev-cache/kaspersky-ca.pem uv run python -m vulnops.workers.orchestration
```

- [ ] **Step 2: Submit an in-range SBOM and verify the loop**

As `admin-demo` (sbom:write), POST a CycloneDX SBOM to `/api/v1/organizations/org-demo/sboms` containing `{"name": "urllib3", "version": "1.26.17", "purl": "pkg:pypi/urllib3@1.26.17"}` (1.26.17 is inside real OSV advisory ranges fixed in 1.26.18+). Verify:
- orchestrator log shows the SBOM event delivered;
- `SELECT vulnerability_id, match_class, state, priority, policy_version FROM exposures;` returns deterministic rows;
- `remediation_cases` has auto-created cases linked via `case_exposures`, with SLA due dates.

- [ ] **Step 3: Record evidence**

Add a dated row to the evidence log in `docs/operations/integrated-staging.md` (purl/version used, matched advisory, exposure/case ids, SLA due date). Update the `Exposure generation/candidate queue` row in `docs/acceptance-matrix.md`: orchestration gap closed; candidate review UI still open.

- [ ] **Step 4: Commit**

```bash
git add docs/operations/integrated-staging.md docs/acceptance-matrix.md
git commit -m "docs(staging): record closed-loop exposure orchestration evidence"
```

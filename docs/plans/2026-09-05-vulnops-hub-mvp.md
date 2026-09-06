# VulnOps Hub MVP Implementation Plan

> **Execution status:** Partially implemented as the M1 technical preview. This
> is the original plan, not proof that every task or exit gate is complete. Use
> `docs/acceptance-matrix.md` for current evidence and open work.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the smallest self-hosted control plane that turns trusted asset,
SBOM, scanner, and intelligence evidence into explainable remediation cases with
safe lifecycle handling.

**Architecture:** Implement a Python modular monolith with an OpenAPI-first
service, PostgreSQL transactional state, object-backed source snapshots, and
asynchronous idempotent workers. DefectDojo, Vulnerability-Lookup, and Wazuh
remain external adapters; the Hub owns identity, exposure evaluation, policy,
cases, verification, and audit/outbox events.

**Tech Stack:** Python 3.12, FastAPI, Pydantic, SQLAlchemy/Alembic,
PostgreSQL, Redis or Valkey-backed worker queue, S3-compatible object storage,
OpenTelemetry, pytest, Testcontainers, Docker Compose, and OpenAPI 3.1.

**Design references:** docs/architecture.md, docs/data-model.md,
docs/modules.md, docs/api.md, docs/deployment.md, docs/mvp-roadmap.md, and
docs/decisions/0001-reuse-first-orchestration.md.

**Historical execution note:** The initial repository contained documentation
only. The core implementation described below now exists, but remaining items
must still be executed from tests in a feature worktree. Follow
@superpowers:test-driven-development for every behavior change and
@superpowers:verification-before-completion before each commit/merge claim.

## Task 1: Create a runnable, observable service skeleton

**Files:**

- Create: pyproject.toml
- Create: src/vulnops/main.py
- Create: src/vulnops/config.py
- Create: src/vulnops/api/health.py
- Create: tests/api/test_health.py
- Create: docker-compose.yml
- Create: .env.example
- Create: Makefile

**Step 1: Write the failing health contract test.**

~~~python
def test_liveness_returns_service_identity(client):
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["service"] == "vulnops-hub"
~~~

**Step 2: Run the focused test and verify it fails because the application does
not exist.**

~~~text
uv run pytest tests/api/test_health.py -q
Expected: FAIL during import or route lookup.
~~~

**Step 3: Implement only application construction, validated configuration,
request IDs, and live/ready health routes.**

The ready route must check database connectivity but never expose credentials or
internal exception text.

**Step 4: Re-run the focused test, then the complete unit test suite.**

~~~text
uv run pytest tests/api/test_health.py -q
uv run pytest -q
Expected: PASS.
~~~

**Step 5: Commit the atomic bootstrap.**

~~~text
git add pyproject.toml src tests docker-compose.yml .env.example Makefile
git commit -m "feat: bootstrap hub service"
~~~

## Task 2: Implement source snapshots, audit events, and transactional outbox

**Files:**

- Create: src/vulnops/db/models/source_snapshot.py
- Create: src/vulnops/db/models/audit_event.py
- Create: src/vulnops/db/models/outbox_event.py
- Create: src/vulnops/db/migrations/
- Create: src/vulnops/domain/provenance.py
- Create: tests/domain/test_provenance.py
- Create: tests/integration/test_outbox_transaction.py

**Step 1: Write a failing test proving an accepted snapshot and its outbox event
commit together.**

~~~python
def test_snapshot_and_event_are_atomic(session, source_snapshot_factory):
    snapshot = source_snapshot_factory(content=b'{"id":"CVE-2026-1"}')
    persist_snapshot_with_event(session, snapshot)
    assert count_rows(session, "source_snapshots") == 1
    assert count_rows(session, "outbox_events") == 1
~~~

**Step 2: Verify the test fails before persistence exists.**

~~~text
uv run pytest tests/domain/test_provenance.py -q
Expected: FAIL with missing import or table.
~~~

**Step 3: Add schema and service.**

Use a content SHA-256, source identity, provider timestamp, cursor, parser
version, object URI, validation state, and correlation ID. Require an audit
event/evidence reference for every state-changing command.

**Step 4: Add rollback and duplicate-idempotency tests.**

Rollback must leave neither row. Repeated content under the same natural key
must return the original snapshot and never emit a duplicate event.

**Step 5: Run unit plus real PostgreSQL integration tests and commit.**

~~~text
uv run pytest tests/domain/test_provenance.py tests/integration/test_outbox_transaction.py -q
git commit -am "feat: add provenance and transactional outbox"
~~~

## Task 3: Implement canonical assets, components, and SBOM ingestion

**Files:**

- Create: src/vulnops/assets/models.py
- Create: src/vulnops/assets/reconciliation.py
- Create: src/vulnops/sbom/parser.py
- Create: src/vulnops/sbom/service.py
- Create: src/vulnops/api/sboms.py
- Create: tests/assets/test_alias_reconciliation.py
- Create: tests/sbom/test_cyclonedx_parser.py
- Create: tests/sbom/test_spdx_parser.py
- Create: tests/api/test_submit_sbom.py
- Create: tests/fixtures/sbom/

**Step 1: Write failing tests for identity preservation and an ambiguous alias.**

~~~python
def test_same_hostname_from_two_live_assets_is_ambiguous(asset_service):
    result = asset_service.reconcile_alias("hostname", "api-01")
    assert result.status == "ambiguous"
    assert result.asset_id is None

def test_cyclonedx_component_preserves_purl_and_raw_version(parser, bom):
    occurrence = parser.parse(bom).components[0]
    assert occurrence.purl == "pkg:pypi/urllib3@1.26.18"
    assert occurrence.raw_version == "1.26.18"
~~~

**Step 2: Run tests and confirm parsing/reconciliation is absent.**

**Step 3: Implement minimally.**

Accept CycloneDX JSON and SPDX JSON; persist immutable document metadata, retain
raw identifier/version, normalize purl, and produce an ambiguity record rather
than merging on hostname/IP alone.

**Step 4: Add malformed-document, duplicate-upload, and parser-version replay
tests.**

The replay test must prove an older source snapshot can be processed under an
explicit parser version without mutating raw evidence.

**Step 5: Run focused/integration tests and commit.**

~~~text
uv run pytest tests/assets tests/sbom tests/api/test_submit_sbom.py -q
git commit -am "feat: ingest assets and SBOM component evidence"
~~~

## Task 4: Implement intelligence adapter contracts and policy fixtures

**Files:**

- Create: src/vulnops/intelligence/contracts.py
- Create: src/vulnops/intelligence/vulnerability_lookup.py
- Create: src/vulnops/intelligence/osv.py
- Create: src/vulnops/intelligence/epss.py
- Create: src/vulnops/intelligence/kev.py
- Create: src/vulnops/intelligence/models.py
- Create: tests/intelligence/test_vulnerability_lookup_contract.py
- Create: tests/intelligence/test_osv_contract.py
- Create: tests/intelligence/test_epss_contract.py
- Create: tests/fixtures/intelligence/

**Step 1: Write contract tests using recorded, non-secret provider responses.**

~~~python
def test_osv_batch_match_keeps_source_timestamp(osv_adapter, fixture_http):
    record = osv_adapter.lookup_batch([component_fixture])[0]
    assert record.source == "osv"
    assert record.retrieved_at is not None
    assert record.source_url.startswith("https://")
~~~

**Step 2: Verify all adapters fail until their interface is implemented.**

**Step 3: Implement adapter interface and source snapshot capture.**

The interfaces return normalized advisory assertions plus source provenance.
They must not update Cases. Add a configuration-gated
Vulnerability-Lookup adapter and direct OSV/EPSS/KEV adapters. NVD/CSAF are
contract placeholders in this milestone unless fixture coverage is ready.

**Step 4: Add retry, rate-limit, stale-cache, and schema rejection tests.**

An upstream failure must mark health stale/degraded and must not delete existing
advisory assertions.

**Step 5: Run contract tests and commit.**

~~~text
uv run pytest tests/intelligence -q
git commit -am "feat: add provenance-aware intelligence adapters"
~~~

## Task 5: Implement deterministic matching and explainable risk policy

**Files:**

- Create: src/vulnops/matching/service.py
- Create: src/vulnops/matching/versioning.py
- Create: src/vulnops/matching/models.py
- Create: src/vulnops/risk/policy.py
- Create: src/vulnops/risk/simulation.py
- Create: tests/matching/test_purl_range_match.py
- Create: tests/matching/test_candidate_cpe_match.py
- Create: tests/risk/test_kev_escalation.py
- Create: tests/risk/test_policy_simulation.py

**Step 1: Write failing tests for three non-negotiable outcomes.**

~~~python
def test_purl_in_osv_range_creates_deterministic_exposure(...):
    exposure = evaluate(...)
    assert exposure.match_class == "deterministic"

def test_cpe_name_only_is_candidate_not_case(...):
    exposure = evaluate(...)
    assert exposure.match_class == "candidate"
    assert exposure.case_id is None

def test_kev_critical_internet_asset_selects_p0_policy(...):
    result = evaluate_risk(...)
    assert result.priority == "P0"
~~~

**Step 2: Run the test group and verify all initial expectations fail.**

**Step 3: Implement version-scheme-aware range evaluation.**

Support only purl/ecosystem schemes present in fixtures. Unsupported schemes
must produce candidate or unsupported results, never a guessed fixed state.
Persist match explanation, matcher version, source evidence, policy version,
factors, and limitations.

**Step 4: Add idempotent re-evaluation and policy simulation tests.**

Changing an advisory range or policy must produce an audit event and a new
evaluation generation without duplicate active exposure rows.

**Step 5: Execute all matching/risk tests and commit.**

~~~text
uv run pytest tests/matching tests/risk -q
git commit -am "feat: evaluate exposures with explainable policy"
~~~

## Task 6: Implement cases, SLA, decisions, verification, and reopening

**Files:**

- Create: src/vulnops/cases/models.py
- Create: src/vulnops/cases/service.py
- Create: src/vulnops/cases/sla.py
- Create: src/vulnops/cases/verification.py
- Create: src/vulnops/api/cases.py
- Create: tests/cases/test_state_machine.py
- Create: tests/cases/test_risk_acceptance_expiry.py
- Create: tests/cases/test_verification_coverage.py
- Create: tests/api/test_case_transitions.py

**Step 1: Write failing state-machine and safe-closure tests.**

~~~python
def test_incomplete_scan_cannot_close_case(case_service, incomplete_scan):
    result = case_service.verify(case_id, incomplete_scan)
    assert result.status == "insufficient_evidence"
    assert get_case(case_id).status != "closed"

def test_expired_acceptance_reopens_case(case_service, clock):
    clock.advance(days=31)
    case_service.process_expirations()
    assert get_case(case_id).status == "triage"
~~~

**Step 2: Run tests and verify state transition services do not exist.**

**Step 3: Implement commands, roles, policy gates, SLA clocks, and append-only
events.**

Cases are created from policy-qualified exposures only. Approval records require
scope, expiry, rationale, evidence, and authorized approvers. External ticket
delivery is outbox-driven.

**Step 4: Add reopen, concurrent-update, and non-authoritative manual
attestation tests.**

New confirmed evidence must reopen a closed case. A stale If-Match precondition
must fail safely. Manual attestation cannot close a case without an approval
path.

**Step 5: Run tests, simulate a full lifecycle, and commit.**

~~~text
uv run pytest tests/cases tests/api/test_case_transitions.py -q
git commit -am "feat: govern remediation cases and verification"
~~~

## Task 7: Build DefectDojo and Wazuh evidence bridges

**Files:**

- Create: src/vulnops/integrations/defectdojo.py
- Create: src/vulnops/integrations/wazuh.py
- Create: src/vulnops/integrations/mapping.py
- Create: src/vulnops/workers/ingestion.py
- Create: tests/integrations/test_defectdojo_bridge.py
- Create: tests/integrations/test_wazuh_bridge.py
- Create: tests/fixtures/defectdojo/
- Create: tests/fixtures/wazuh/

**Step 1: Write recorded-payload tests for asset mapping and source links.**

**Step 2: Verify bridges do not create exposed/case data before the matching
module evaluates their evidence.**

**Step 3: Implement read-only ingestion first.**

DefectDojo bridge imports test/finding references and reimport metadata. Wazuh
bridge imports inventory/detection observations. Capture scan completeness,
target/service scope, and source identifiers.

**Step 4: Add replay and mapping-conflict tests.**

Conflicting asset hints create reconciliation work; they never select an arbitrary
asset. Replaying the same provider record emits no duplicate Case or external
ticket event.

**Step 5: Run bridge plus end-to-end fixture test and commit.**

~~~text
uv run pytest tests/integrations -q
uv run pytest tests/e2e/test_defectdojo_to_closed_case.py -q
git commit -am "feat: ingest DefectDojo and Wazuh evidence"
~~~

## Task 8: Harden deployment, contracts, and operator documentation

**Files:**

- Create: openapi/openapi.yaml
- Create: deploy/helm/vulnops-hub/
- Create: docs/operations/runbook.md
- Create: docs/operations/backup-restore.md
- Create: docs/operations/adapter-onboarding.md
- Create: .github/workflows/ci.yml
- Create: .github/workflows/security.yml
- Create: tests/contract/

**Step 1: Add a failing OpenAPI conformance test for one ingestion and one case
transition endpoint.**

**Step 2: Generate/validate the OpenAPI document and make the tests pass.**

**Step 3: Add Compose/Helm deployment assets with non-secret defaults and
readiness checks.**

Include PostgreSQL, object storage, queue, API, and worker profiles. External
integrations must be optional and disabled by default.

**Step 4: Add CI gates.**

Run formatting, types, unit tests, integration/contract tests, dependency
checks, secret scanning, SBOM generation, and container scan where credentials
permit.

**Step 5: Perform a clean install, run the fixture e2e path, verify backup
restore instructions, and commit.**

~~~text
docker compose up --build
uv run pytest -q
git commit -am "chore: document and verify deployable MVP"
~~~

## Final verification checklist

- [ ] Every MVP acceptance criterion in docs/mvp-roadmap.md has a named fixture
  or test; access control remains open.
- [ ] Every source adapter records provenance, handles replay, and reports
  freshness.
- [x] No CPE/name-only candidate creates a case automatically.
- [x] No missing/failed scan output closes a case.
- [ ] Policy changes and case state changes produce audit events in the fixture
  suite; complete audit coverage for every policy evaluation remains open.
- [ ] DefectDojo/Wazuh fixtures retain original source IDs and DefectDojo covers
  conflicting hints; complete conflict coverage across both adapters remains
  open.
- [ ] OIDC/service scopes, raw-evidence authorization, and secret redaction are
  tested.
- [ ] Database/object-storage restore and outbox replay are rehearsed.
- [x] CI is green from a clean clone for commit `ac51721` (run `34003716095`;
  Security run `34003716213`).

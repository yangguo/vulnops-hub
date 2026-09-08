# Exposure Generation Orchestration — Design

> **Date:** 2026-09-08
> **Status:** Approved design, pending implementation plan
> **Goal:** Close the M1 gap recorded in the staging evidence log — ingested
> evidence (SBOM / DefectDojo / Wazuh) currently stops at evidence retention;
> no code consumes outbox events to generate exposures and remediation cases.

## Problem

The evidence layer works end to end (verified in staging 2026-09-08): the
three ingestion paths persist `source_snapshots` and emit outbox events
(`vulnops.sbom.processed.v1`, `vulnops.evidence.defectdojo.ingested.v1`,
`vulnops.evidence.wazuh.ingested.v1`). `MatchingService` implements the
deterministic/candidate/not_affected decision tree and is covered by fixture
tests. `RiskPolicyEngine` computes priority from match class, KEV, EPSS, and
asset context. The `exposures`, `match_evidence`, and `case_exposures` tables
and the `CaseService.create_case(exposures=[...])` contract all exist.

What is missing is the orchestration that connects them: nothing consumes the
outbox, queries intelligence for advisories, runs the matcher, or creates
exposures and cases. The `exposures` table has no writer.

## Decisions (confirmed with the product owner)

1. **Trigger mechanism: DB outbox polling worker.** A new process polls
   `outbox_events` with a durable cursor. Redis queue-chaining and synchronous
   in-API matching were rejected: the outbox keeps the durable, replayable
   semantics the acceptance matrix's cursor-recovery requirement needs, and
   the existing `delivered_at` / `attempts` columns already model it.
2. **Case creation boundary: deterministic matches create cases
   automatically; candidates do not.** `confirmed` / `deterministic` matches
   create a remediation case with SLA clock. `candidate` / `corroborated`
   matches create only an exposure (state `candidate`) for operator review.
   `not_affected` matches are recorded and stay silent. Ambiguous asset
   mapping never creates a case. A kill switch `CASE_AUTO_CREATE_ENABLED`
   (default on) disables automatic case creation.

## Architecture

New module `src/vulnops/workers/orchestration.py`, run as its own container
service `orchestrator` in the root compose (command
`python -m vulnops.workers.orchestration`).

```text
loop:
  rows = SELECT * FROM outbox_events
         WHERE delivered_at IS NULL AND attempts < MAX_ATTEMPTS
         ORDER BY created_at LIMIT batch FOR UPDATE SKIP LOCKED
  for row in rows:
    try:
      handler[row.event_type](row)          # one DB transaction per event
      mark delivered_at                      # same transaction
    except:
      rollback; attempts += 1; backoff; SourceStatus degraded
```

### Handlers per event type

| Event | Flow |
| --- | --- |
| `vulnops.sbom.processed.v1` | Load the SBOM's `component_occurrences` → `OSVAdapter.lookup_batch(purl, version)` → `apply()` upserts `Vulnerability` / `AffectedRange` / `AdvisoryAssertion` → for each (occurrence, advisory) run `MatchingService.evaluate` |
| `vulnops.evidence.defectdojo.ingested.v1` | Payload carries cve, purl, mapping status, scan metadata. If a purl exists, query OSV for the real advisory (replacing the bridge's evaluation stub). A `verified` finding supplies `scanner_evidence` → the matcher's `confirmed` path. |
| `vulnops.evidence.wazuh.ingested.v1` | Package inventory events. The recorded payload carries agent id, package metadata, and cve (usually `unknown`); it has no purl. The orchestrator does not guess purls from names — name-only matches stay `candidate` under the matcher's conservative rule, so Wazuh events today produce candidate-state exposures (review queue), not cases. |

### Match outcomes

| `match_class` | Exposure | Case |
| --- | --- | --- |
| `confirmed` | create/upsert, state `active` | auto-create |
| `deterministic` | create/upsert, state `active` | auto-create |
| `corroborated` | create, state `candidate` | none |
| `candidate` | create, state `candidate` | none |
| `not_affected` | create/upsert, state `not_affected` | none |
| ambiguous mapping | none (bridge already rejects) | none |

Automatic case creation: `CaseService.create_case(...)` with a title derived
from component + vulnerability id, the configured default owner team, the
policy-selected priority, and `exposures=[exposure_id]` so the SLA clock and
audit timeline start. Creation is skipped when an active case already links
the exposure, when mapping is ambiguous, or when
`CASE_AUTO_CREATE_ENABLED=false`.

### Priority and policy

`RiskPolicyEngine.evaluate(PolicyInput(match_class, kev, epss_score, asset
criticality, internet exposure, ...))` selects the policy; the result sets
`exposures.priority` and `exposures.policy_version`. KEV membership comes from
`KEVAdapter.fetch_catalog()` (cached for the process lifetime); EPSS from the
EPSS adapter by CVE. If enrichment sources fail, deterministic matching still
proceeds with `limitations` noting the missing enrichment and the policy
degrades to the un-enriched result — matching is never blocked by enrichment.

### Idempotency

- Exposure natural key: `(organization_id, component_occurrence_id,
  vulnerability_id)`. Re-processing an event upserts: updates
  `last_observed_at`, appends `match_evidence` rows deduplicated by
  `evidence_ref`, and never creates a second case.
- Outbox events are marked `delivered_at` only after the handler transaction
  commits. Failures increment `attempts` with backoff; events past
  `MAX_ATTEMPTS` stop being picked up (poison) and log an error.
- SBOM-side dedup reuses the existing content-addressed submission contract.

### Error handling

- Intelligence network failures: event not delivered, backoff retry,
  `SourceStatus` set to `degraded` / `stale` — visible to the source-health
  surface required by the acceptance matrix.
- Ecosystems the versioning layer does not support (e.g. `generic` purl
  types): the matcher's `unsupported.ecosystem` rule yields `candidate`;
  no case, no false positive.
- Advisory payloads that fail validation are rejected by the adapter
  `validate()` step and recorded, never silently dropped.

## Configuration additions

| Setting | Default | Purpose |
| --- | --- | --- |
| `ORCHESTRATOR_POLL_INTERVAL_SECONDS` | `5` | Outbox poll cadence |
| `ORCHESTRATOR_BATCH_SIZE` | `50` | Events per poll |
| `ORCHESTRATOR_MAX_ATTEMPTS` | `8` | Poison threshold |
| `CASE_AUTO_CREATE_ENABLED` | `true` | Kill switch for automatic case creation |
| `DEFAULT_CASE_OWNER_TEAM` | `unassigned` | Owner team for auto-created cases |

## Testing (TDD)

Unit and integration tests in `tests/workflows/test_exposure_orchestration.py`
(fixtures injected via the adapters' existing `raw_fixture` / `http_client`
seams):

1. SBOM event → OSV fixture advisory in range → `deterministic` exposure +
   auto-created case with SLA clock and CaseExposure link.
2. Replay the same event → no new exposure, no new case,
   `last_observed_at` updated.
3. Out-of-range version → `not_affected` exposure, no case.
4. Candidate (name-only / unsupported ecosystem / CPE-only) → exposure with
   `state=candidate`, no case.
5. DefectDojo `verified` finding + purl → `confirmed` path creates case;
   unverified finding → `deterministic` only.
6. Wazuh event without purl → candidate, no case.
7. `CASE_AUTO_CREATE_ENABLED=false` → exposure created, no case.
8. Ambiguous mapping → no exposure, no case.
9. KEV escalation fixture → exposure priority reflects the policy and
   `policy_version` is recorded.
10. Outbox delivery marking: handler failure increments `attempts`; success
    sets `delivered_at`; poison events are skipped.

## Staging verification plan

Re-run the 2026-09-08 staging scenario with the orchestrator enabled and a
SBOM component whose version falls inside a real OSV advisory range (e.g.
`pkg:pypi/urllib3@1.26.17`), then re-fetch the DefectDojo finding. Expected:
deterministic exposure from SBOM evidence, automatic case, and the evidence
log gains the closed-loop row. Host-side runs need
`SSL_CERT_FILE=D:\dev-cache\kaspersky-ca.pem` for httpx TLS under the local
interception proxy.

## Out of scope

- Product-level HTTP polling adapters for DefectDojo/Wazuh (separate slice;
  the fetch script remains the stand-in).
- Source-health API/UI.
- Candidate review workflow (queue content exists via exposures in
  `candidate` state; UI comes with the operator console slice).

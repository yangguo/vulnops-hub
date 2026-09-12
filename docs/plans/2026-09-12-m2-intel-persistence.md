# M2 intel persistence and KEV refresh

## Scope

Persist normalized intelligence at enrichment boundaries:

- `Vulnerability`, `VulnerabilityAlias`, `AffectedRange`, and per-source
  `AdvisoryAssertion` rows are upserted when OSV (orchestrator), KEV catalog
  refresh, or Vulnerability-Lookup (when a DB session is wired) produce
  `AdvisoryRecord` instances.
- KEV catalog refresh runs on orchestrator startup, on a configurable interval
  inside the orchestrator loop (`KEV_REFRESH_INTERVAL_SECONDS`, default 24h),
  and via `python -m vulnops.workers.intel_refresh` for a dedicated poller.

## Behavior

| Source | Trigger | Persisted fields |
| --- | --- | --- |
| OSV | SBOM / DefectDojo orchestration after live query | CVE id, aliases, affected ranges, OSV assertion payload |
| KEV | Startup + periodic refresh | KEV flag, due date in assertion content, vulnerability stub |
| Vulnerability-Lookup | Optional `session` on adapter | CVE metadata, CVSS when present |

Matching still uses live OSV responses from `lookup_batch`; persistence is for
reuse, audit, and KEV fallback when the in-memory catalog is empty.

KEV escalation checks the in-memory catalog first, then `AdvisoryAssertion`
rows with `source=kev` and `kev=true`.

## Residual risks

- CVEs removed from the CISA catalog are not automatically cleared in intel
  tables; stale `kev=true` rows may remain but do not affect escalation while
  the in-memory catalog is loaded (`is_kev` uses the catalog for negatives).
- `AffectedRange` stable ids omit package name when only ecosystem/purl differ
  ambiguously; collision risk is low for OSV-sourced ranges.
- EPSS remains on-demand (not bulk-persisted).
- OSV partial failures still mark adapter health stale without deleting prior
  assertions.
- Vulnerability-Lookup persistence is opt-in via adapter session wiring; VEX
  lookups do not yet persist full VL payloads.

# M2 Slices — Design

> **Date:** 2026-09-09
> **Status:** Approved direction (ADR 0002 + revised roadmap); per-slice
> details recorded here. Supersedes `scripts/sandbox_fetch.py` as the
> production ingestion path.

Six slices, implemented in order. Every slice keeps the standing rules:
evidence bridges never create cases; adapters preserve provenance and support
idempotent replay; the orchestrator is the sole exposure/case writer.

## Slice 1 — Product-level polling adapters (DefectDojo, Wazuh)

**Module:** `src/vulnops/workers/polling.py`, run as the `poller` compose
service (`python -m vulnops.workers.polling`).

Loop per configured source: `discover(cursor)` → validate → wrap raw records
as ingestion jobs `{"source", "payload", "organization_id", "idempotency_key"}`
→ LPUSH `vulnops:ingest` (the existing bridge pipeline applies them) →
checkpoint cursor + health into the `source_statuses` table **only after the
enqueue commits**. The bridges remain the apply layer; their snapshot dedup
makes full re-listing safe, so the Wazuh cursor is simply the last successful
poll time.

Fetchers:
- `DefectDojoClient.fetch_findings(cursor, limit)`: GET
  `/api/v2/findings/?ordering=id&limit=N&id__gt=<cursor>`; next cursor = max
  finding id seen; auth `Authorization: Token <DEFECTDOJO_API_TOKEN>`.
- `WazuhClient`: JWT via `POST /security/user/authenticate?raw=true` (basic
  auth), then `GET /agents` and `GET /syscollector/{agent_id}/packages` per
  agent; payloads shaped `{"agent": ..., "package": ...}` exactly as
  `WazuhBridge.ingest_event` expects (same as the fetch script).

Settings additions: `defectdojo_api_token`, `defectdojo_poll_interval_seconds`
(300), `wazuh_api_user`, `wazuh_api_password`, `wazuh_poll_interval_seconds`
(300), `poll_organization_id` ("org-demo"), `poll_page_size` (100).
Sources are enabled by their base URL + credentials being configured; a
source without config is skipped with a log line.

Health: after each cycle, upsert `source_statuses` — `fresh` on success,
`stale` + error on failure, `last_checked_at` always. The source-health API
(slice 3) reads this table.

Tests: fake http clients; pagination + cursor advance; enqueue shape equals
the fetch script's; checkpoint only after enqueue; failure marks stale and
keeps the cursor.

## Slice 2 — Source-health API

`GET /api/v1/organizations/{org}/source-health` — auditor/owner-readable —
returning rows from `source_statuses` plus freshness classification. Minimal
console panel (list + freshness badge). Data layer already exists.

## Slice 3 — CSV/CMDB asset import

`POST /api/v1/organizations/{org}/assets/import` (multipart or JSON rows):
columns mapped by header (name/hostname, ip, criticality, owner_team,
service). Reuses the existing asset reconciliation (`assets/reconciliation.py`)
for identity resolution; returns created/updated/skipped counts. CSV via
stdlib `csv` module. Capability: `sbom:write`-equivalent — reuse admin or
`asset:write` if the matrix already defines one (check `auth/models.py`).

## Slice 4 — Candidate review API + UI

Exposures in `candidate` state already exist. Add:
- `GET /api/v1/organizations/{org}/exposures?state=candidate` (paginated).
- `POST .../exposures/{id}/review` with `{"decision": "confirmed"|
  "not_affected"|"dismissed", "reason": str}` — reviewer capability
  (`risk:request`? use owner) writes a decision audit event and moves state;
  `confirmed` promotes to `active` and lets the orchestrator's case guard
  pick it up on the next occurrence (no direct case creation — the review
  outcome is recorded; case creation on promotion follows the orchestrator's
  existing path when the source re-observes, keeping "matching decides").
- Minimal console page: candidate list + decision buttons.

## Slice 5 — Jira link-back (ADR 0002)

In the DefectDojo handler (orchestration), after case creation for
scanner-confirmed cases: if the raw finding payload carries a Jira issue key
(DD exposes it on the finding when its Jira integration is enabled), record
it on the case's external-ticket reference with provenance
`"jira via defectdojo finding <id>"`. Read-only: the Hub never mutates DD.

## Slice 6 — VEX via Vulnerability-Lookup

`VULNERABILITY_LOOKUP_BASE_URL` + `VULNERABILITY_LOOKUP_API_KEY` settings;
an adapter method fetches VEX statements for a CVE; the orchestrator's
evaluate call passes `vex_status` (not_affected → exposure recorded
not_affected, no case; affected → confirmed). Best-effort: failures never
block matching (same rule as KEV/EPSS enrichment).

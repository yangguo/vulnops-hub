# M2 Greenbone via DefectDojo — Design

> **Date:** 2026-09-11
> **Status:** Implemented; live poller verification pending
> **Decision boundary:** [ADR 0002](../../decisions/0002-projection-and-connector-leverage.md)

## Decision and ADR compliance

Greenbone/OpenVAS remains an evidence producer behind DefectDojo's import and
parser. VulnOps does not add a Greenbone/OpenVAS API client, XML parser,
scanner bridge, or second poller. The existing DefectDojo poller (with
`scripts/sandbox_fetch.py` available for a direct sandbox run) continues to
feed the existing ingestion worker and `DefectDojoBridge`.

This slice makes the route demonstrable by preserving scanner identity from
the DefectDojo finding payload and proving the existing orchestration path for
verified findings. DefectDojo remains the owner of scanner parsing and finding
state; the Hub only reads evidence and Jira metadata.

## Provenance contract

`DefectDojoBridge._extract_scan_metadata` retains the existing scan
completeness fields and adds generic scanner identity:

```json
{
  "scope_status": "complete",
  "credentials_status": "authenticated",
  "scan_id": "scan-2026-09-05-001",
  "test_id": 987,
  "reimport_version": 2,
  "scanner": "Greenbone/OpenVAS",
  "scan_type": "OpenVAS Scan",
  "test_type": "OpenVAS Scan"
}
```

The DefectDojo findings-list request includes `related_fields=true` because
production list records commonly expose `test` and `found_by` as IDs. The
extractor reads the scanner label from
`related_fields.test.test_type.name` and the test ID from
`related_fields.test.id`, while accepting DefectDojo-shaped scalar or nested
values for `test_type`, optional `test_type_name`, `found_by`, `scan_type`,
`reimport.scan_type`, and the nested `test` object used by Hub fixtures. Any
case-insensitive Greenbone or OpenVAS signal normalizes to
`Greenbone/OpenVAS`; other findings retain their first useful tool/test label,
such as `Trivy`.

The same values remain in the existing `payload.scan_metadata` object. The
outbox payload also exposes `scanner`, `scan_type`, and `test_type` at the top
level for operator filtering. The ingestion audit reason includes the short
scanner label and scan type. No table or public API response changes are
needed, so OpenAPI and frontend types are unchanged.

## Ingest-to-orchestrate path

```text
Greenbone/OpenVAS report
  → DefectDojo Import Scan/Reimport Scan
  → DefectDojo finding API
  → existing DefectDojo poller or sandbox_fetch.py
  → ingestion worker
  → DefectDojoBridge source snapshot + audit + outbox
  → existing outbox orchestrator
  → scanner_confirmed exposure
  → remediation case + DefectDojo Jira issue-key link-back (when present)
```

`verified=true` still creates the same matcher input,
`scanner_evidence={"scanner_confirmed": true, "finding_id": ...}`, with
scanner and scan type added only as observability fields. The handler remains
generic: Greenbone/OpenVAS is not a special case, and verified findings from
other scanners use the same confirmed path. Exposure identity remains
`defectdojo:<finding_id>` and replay continues to upsert one exposure/case
without duplicating snapshots, outbox rows, audit rows, or Jira link-back.

## Verification boundary

The fixture suite covers the Greenbone/OpenVAS DD import shape, nested generic
scanner provenance, replay idempotency, and the verified finding → confirmed
exposure → case/Jira path. It does not start a real Greenbone server; report
parsing and scan-type behavior remain DefectDojo-owned and are exercised in
the staging runbook through the DefectDojo UI.

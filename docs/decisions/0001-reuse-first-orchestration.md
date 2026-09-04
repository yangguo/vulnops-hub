# ADR 0001: Reuse-first orchestration architecture

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The desired platform must ingest public vulnerability intelligence, local asset
and SBOM information, and heterogeneous scanner results; then manage an
evidence-backed remediation lifecycle. Existing open-source tools cover large
parts of this scope but have different data models and operational boundaries.

## Decision

Build VulnOps Hub as a modular orchestration/control plane. It owns:

- canonical asset/component identity and evidence references;
- evaluated exposures and matching confidence;
- versioned risk/SLA policy;
- remediation cases, exceptions, verification, reopening, and audit events.

It consumes DefectDojo, Vulnerability-Lookup, Wazuh, Greenbone/OpenVAS, and
other compatible systems through adapters. It does not fork or copy their code
as part of the MVP.

## Consequences

### Positive

- Reuses mature scanner parsing, intelligence correlation, and endpoint/scanner
  capabilities.
- Reduces duplicate CVE/feed operations and upstream upgrade burden.
- Keeps asset/SBOM correlation and lifecycle rules explicit, testable, and
  independent of any one scanner.
- Gives each data element a clear system-of-record boundary.

### Negative

- Requires robust identity reconciliation and adapter contract testing.
- Operations must monitor upstream freshness and integration health.
- Users may see related workflow in both the Hub and DefectDojo unless the
  projection/synchronization policy is carefully configured.
- Deployment licensing must be reviewed per integrated component.

## Guardrails

- No case is created from a global CVE alone.
- No automatic closure is based solely on absence from a failed/partial scan.
- Every adapter preserves source provenance and supports idempotent replay.
- New connectors require a documented source of truth, failure mode, fixture,
  mapping, and operational owner.

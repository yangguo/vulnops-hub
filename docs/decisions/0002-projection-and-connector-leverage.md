# ADR 0002: Projection and connector leverage strategy for M2

- **Status:** Accepted
- **Date:** 2026-09-09
- **Supersedes:** parts of the M2 roadmap scope (`docs/mvp-roadmap.md`) that
  called for a direct Greenbone bridge and a Hub-owned Jira/ServiceNow
  projection; complements [ADR 0001](0001-reuse-first-orchestration.md).

## Context

M2 must get a pilot team running its normal remediation cycle. The project is
maintained by a single engineer assisted by tooling, so every self-built
connector carries a permanent maintenance cost (parser drift, API changes,
fixture upkeep, operational ownership). Three planned M2 items overlap with
capabilities that already exist in integrated upstream systems:

- DefectDojo natively parses Greenbone reports (scanner ingestion is its core
  competency).
- DefectDojo ships a battle-tested, finding-grained Jira integration.
- Vulnerability-Lookup already aggregates VEX/CSAF content.

The M2 exit gate requires a pilot team running the remediation cycle — not
ownership of connectors.

## Decision

1. **Greenbone evidence enters through DefectDojo.** No Hub-native Greenbone
   bridge. Greenbone/OpenVAS stays an evidence producer behind DefectDojo's
   parser, exactly like every other scanner.
2. **Jira projection for scanner-confirmed cases rides DefectDojo's native
   integration.** The Hub performs one small job: when creating a case from a
   DefectDojo finding, read back the finding's Jira issue key (if DD's Jira
   integration has pushed it) and record it in the case's external-ticket
   reference.
3. **Scope boundary — which cases get Jira tickets:** only scanner-confirmed
   cases that correspond to a DefectDojo finding. SBOM-only and Wazuh
   candidate cases stay Hub-internal during the pilot; they have no DefectDojo
   object to project.
4. **ServiceNow and case-level Jira projection are deferred.** If pilot
   feedback proves the DefectDojo route insufficient, a Hub outbox projector
   becomes a properly specified follow-up rather than speculative scope.
5. **VEX/CSAF statements are consumed via Vulnerability-Lookup** (already the
   preferred intelligence service per the research decision); the Hub keeps
   VEX as time-versioned evidence feeding match policy, per its guardrails.

Unchanged from the original M2 plan: product-level polling adapters for
DefectDojo and Wazuh (these ARE the integration with those systems and cannot
be delegated further), CSV/CMDB import, source-health API/UI, and the
candidate review UI.

## Consequences

### Positive

- Roughly one third of the planned M2 connector code is removed; the pilot
  starts sooner.
- Jira/Greenbone semantics are maintained upstream by a large community
  instead of by this project.
- System-of-record boundaries stay explicit: DefectDojo owns findings,
  the Hub owns remediation decisions.

### Negative

- Case-grained Jira status is approximate: a multi-finding case reflects the
  state of the finding(s) DD projected, not a dedicated Jira issue per case.
- SBOM-originated cases are invisible to Jira during the pilot; if this
  blocks the pilot team, the deferred projector must be specified against
  real requirements.
- Users see related workflow in both DefectDojo and the Hub; the projection
  policy here and in the operations docs must state who owns what.
- ServiceNow is unlikely to be covered by DefectDojo community edition; a
  pilot requirement for it reopens scope with little notice.

## Guardrails

- The Hub never mutates a DefectDojo finding; it reads findings and their
  Jira metadata only (existing read-only bridge rule).
- The external-ticket reference on a case records provenance
  ("jira via defectdojo finding <id>"), never a blind URL.
- If the pilot later needs case-level projection, the outbox event stream
  (`vulnops.case.created.v1` and successors) is the intended feed; no new
  event shapes are invented for it.

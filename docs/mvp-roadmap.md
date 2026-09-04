# MVP and Roadmap

## 1. Product thesis

The first useful release is not a universal security platform. It proves one
end-to-end loop:

~~~text
asset/SBOM or scanner evidence
  → high-confidence vulnerability match
  → explainable priority and owner
  → SLA-governed remediation case
  → positive verification
  → closure or evidence-based reopen
~~~

The MVP is successful only if an operator can explain why a case exists, who
owns it, what evidence supports it, what SLA applies, and why it closed or
reopened.

## 2. MVP scope

### Must have

1. Organization, team, asset, service, owner, and criticality model.
2. CSV/CMDB import plus Wazuh endpoint/package observations.
3. CycloneDX JSON and SPDX JSON SBOM ingestion with purl preservation.
4. Intelligence adapter contract and one preferred Vulnerability-Lookup
   integration; direct CISA KEV, FIRST EPSS, and OSV fallback/corroboration.
5. DefectDojo bridge for scanner finding/test evidence and recurring import
   references.
6. Exposure generation for scanner-confirmed and purl/version-range deterministic
   matches; candidate queue for CPE/name heuristics.
7. Versioned transparent risk policy with KEV, EPSS, CVSS, asset criticality,
   internet exposure, and match confidence inputs.
8. Remediation case workflow, owner assignment, priority/SLA clocks, external
   ticket link, audit timeline, and notifications.
9. Evidence-based risk acceptance with expiry and approval.
10. Verification from complete scanner observation, Wazuh package inventory, or
    deployed SBOM; safe closure and reopen rules.
11. Source freshness, coverage gap, and integration-health dashboards/API.
12. OpenAPI contract, migrations, fixtures, unit/integration/contract tests,
    and a secure self-hosted deployment path.

### Must not have

- New scanner engine, new endpoint agent, or comprehensive scanner parser set.
- Automatic risk acceptance, unreviewed patch actions, or closure due to absent
  scan output.
- Full cloud inventory, every national CVE feed, AI remediation agent,
  multi-tenancy, billing, or enterprise GRC replacement.

## 3. MVP acceptance criteria

| Scenario | Acceptance criterion |
| --- | --- |
| Repeated scanner import | The same DefectDojo-linked finding updates one exposure without duplicate case creation; raw evidence remains traceable |
| KEV escalation | A deterministic match on an internet-facing critical asset is prioritized by the active policy, with factors visible |
| SBOM match | A CycloneDX/SPDX purl/version match creates an exposure linked to exact SBOM component evidence |
| Ambiguous mapping | A CPE/name-only match enters review and creates neither a case nor an automatic closure |
| Risk acceptance | Requires configured approval, evidence, expiry, and reopens/escalates on expiry |
| Verification | An incomplete scan cannot close a case; a valid fixed package observation can close only if policy requirements are met |
| Reopen | New scanner-confirmed evidence on a closed case causes reopen with an audit event rather than a second unrelated ticket |
| Source outage | Stale feed health is visible and no existing exposure is silently downgraded |
| Replay | Replaying an ingestion batch is idempotent and does not duplicate cases, events, or external tickets |
| Access | An owner sees only its authorized scope; an auditor sees timeline/evidence metadata without mutation rights |

## 4. Milestones

### M0 — Design and executable contracts

- Freeze canonical data model and terminology.
- Publish OpenAPI and event schemas with example fixtures.
- Create policy fixture set covering KEV, EPSS, candidate matches, exceptions,
  verification, and reopening.
- Build compatibility matrix for target DefectDojo, Vulnerability-Lookup,
  Wazuh, and Greenbone versions.
- Agree data ownership, retention, and approval policy with the first adopter.

**Exit gate:** architecture decisions are reviewed, fixture scenarios map to
acceptance criteria, and no upstream component is being forked by default.

### M1 — Thin vertical slice

- Implement modular core, OIDC/service auth, organization and asset graph.
- Add SBOM parser and source-snapshot store.
- Add Vulnerability-Lookup plus KEV/EPSS/OSV adapters.
- Implement deterministic matching, policy simulation, exposure store, and
  case/SLA workflow.
- Add DefectDojo and Wazuh evidence bridges.
- Add verification/exception/reopen logic and audit/outbox.

**Exit gate:** the full acceptance table is demonstrated against fixture data
and one non-production integrated environment.

### M2 — Operational pilot

- Add Greenbone report/API bridge and Jira/ServiceNow projection.
- Add business-service mappings, improved asset reconciliation, ownership
  escalation, and notification templates.
- Add VEX/CSAF ingestion and review workflow.
- Add operator UI for triage, case timeline, policy explanation, source
  freshness, and coverage gaps.
- Establish backup/restore drill and upgrade/replay procedure.

**Exit gate:** a pilot team runs its normal remediation cycle with measurable
case ownership, SLA, verification, and replay evidence.

### M3 — Scale and ecosystem

- Cloud/Kubernetes/OCI inventory adapters and deployed-SBOM association.
- Policy-as-code review/deployment and historical policy simulation.
- More vendor/CSAF sources, mapping-rule governance, and localized sources
  where legally and technically appropriate.
- Metrics exports, data-retention automation, and performance scaling based on
  measured workload.
- Evaluate multi-organization isolation only after a real need and threat model.

**Exit gate:** extension mechanisms are stable enough for external contributors
without relaxing evidence or audit guarantees.

## 5. Sequencing rules

1. Build identifiers and evidence first; sophisticated scoring without reliable
   identity produces confident noise.
2. Build a reviewable policy engine before dashboards; policy changes must be
   testable and explainable.
3. Make every worker idempotent before adding more feeds.
4. Make closure conservative before optimizing auto-remediation rate.
5. Add a connector only with a documented source of truth, mapping, failure
   mode, replay strategy, and fixture.

## 6. Metrics for the pilot

- percentage of active high-priority exposures with a named owner;
- percentage with evidence freshness inside policy;
- median time from confirmed exposure to assignment and to verification;
- SLA breach rate by business service/owner;
- false-positive/candidate review rate by match method;
- cases closed with positive evidence versus manual attestation;
- reopen rate and reason;
- asset/component identity ambiguity rate;
- external ticket synchronization success;
- source freshness and coverage-gap duration.

These are operating metrics, not promises of security or breach prevention.

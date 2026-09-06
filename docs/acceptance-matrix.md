# MVP Acceptance Matrix

> **Status date:** 2026-09-06
> **Baseline:** M1 technical preview at `ac51721`
> **Purpose:** Separate fixture-level verification from integrated-environment
> and production evidence. A passing fixture does not by itself satisfy the M1
> exit gate.

## Status definitions

| Status | Meaning |
| --- | --- |
| Verified | An executable automated test directly covers the criterion |
| Partial | Core behavior is tested, but one or more required integrations or outcomes are absent |
| Open | The required product capability or evidence does not exist yet |

## Acceptance criteria

| Roadmap scenario | Status | Current evidence | Remaining evidence |
| --- | --- | --- | --- |
| Repeated scanner import | Partial | `tests/integrations/test_defectdojo_bridge.py::test_defectdojo_replay_is_idempotent`; `tests/e2e/test_defectdojo_to_closed_case.py` | Demonstrate real DefectDojo reimport and prove external-ticket/outbox deduplication |
| KEV escalation | Verified | `tests/risk/test_kev_escalation.py::test_kev_critical_internet_asset_selects_p0_policy`; explainability tests in `test_policy_simulation.py` | Repeat against a configured KEV source in integrated staging |
| SBOM match | Verified | CycloneDX/SPDX parser tests; `tests/matching/test_purl_range_match.py::test_purl_in_osv_range_creates_deterministic_exposure` | Demonstrate an uploaded SBOM through asynchronous evaluation in integrated staging |
| Ambiguous mapping | Verified | `tests/matching/test_candidate_cpe_match.py::test_cpe_name_only_is_candidate_not_case`; asset reconciliation tests | Add operator review workflow when the candidate API/UI is implemented |
| Risk acceptance | Verified | `tests/cases/test_risk_acceptance_expiry.py`; self-approval and role tests in `test_review_feedback.py` | Bind approver identity and role to authenticated claims instead of request fields |
| Verification | Verified | `tests/cases/test_verification_coverage.py` covers incomplete, failed, Wazuh, and manual evidence | Demonstrate real Wazuh/scanner observations with recorded coverage |
| Reopen | Verified | `tests/cases/test_state_machine.py::test_new_confirmed_evidence_reopens_closed_case`; expiry test | Demonstrate new real scanner evidence against an existing closed case |
| Source outage | Partial | KEV, EPSS, OSV, and Vulnerability-Lookup contract tests preserve state and mark stale/degraded | Implement source-health API/UI and prove the status is visible to operators |
| Replay | Partial | Source snapshot, SBOM, DefectDojo, and Wazuh idempotency tests | Add durable cursor recovery, external projection deduplication, and replay drill evidence |
| Access | Open | Case list/detail tests cover organization filters without an authenticated actor | Implement OIDC/service authentication, RBAC, raw-evidence authorization, and owner/auditor tests |

## MVP scope coverage

| Must-have area | Status | Notes |
| --- | --- | --- |
| Organization and asset identity | Partial | Organization IDs and asset reconciliation exist; team/service ownership APIs and auth-bound scope remain open |
| CSV/CMDB and Wazuh observations | Partial | Wazuh bridge exists; CSV/CMDB import is open |
| CycloneDX/SPDX ingestion | Verified | API, parser, hashing, persistence, and idempotency tests exist |
| Intelligence adapters | Verified in fixtures | KEV, EPSS, OSV, and Vulnerability-Lookup contract tests exist; staging evidence remains open |
| DefectDojo bridge | Verified in fixtures | Mapping, replay, conflict, and missing-evidence behavior are tested |
| Exposure generation/candidate queue | Partial | Matching behavior exists; operator-facing candidate queue is not exposed |
| Transparent risk policy | Verified in fixtures | Version, simulation, KEV escalation, and factors are tested |
| Case/SLA/audit/notifications | Partial | Workflow, SLA, audit, and outbox writes exist; notification and external-ticket delivery are open |
| Risk acceptance | Partial | Domain behavior exists; authenticated approval identity is open |
| Verification and reopen | Verified in fixtures | Conservative closure and reopen behavior are tested |
| Source health and coverage gaps | Partial | Adapter status models exist; API/UI and operational visibility are open |
| Secure self-hosted deployment | Partial | Compose, Helm, CI, SBOM, scan, and Docker smoke exist; authentication and production certification are open |

## Evidence required to close M1

- [ ] OIDC/service authentication and organization-scoped RBAC tests pass.
- [ ] The full fixture suite is mapped to this matrix without unsupported
  claims.
- [ ] A non-production environment connects to configured sandbox instances of
  Vulnerability-Lookup, DefectDojo, and Wazuh.
- [ ] Source outage, cursor recovery, and replay are demonstrated and retained
  as dated evidence.
- [ ] Backup/restore and outbox replay commands are executed against the actual
  supported deployment topology.
- [ ] The release commit has successful CI and Security workflow links.
- [ ] Known limitations and operator safeguards are reviewed for the release.

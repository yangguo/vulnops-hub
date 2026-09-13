# MVP Acceptance Matrix

> **Status date:** 2026-09-13
> **Baseline:** `main` at `d2958482`, with M2 PURL acceptance work on `830505d0`
> **Purpose:** Separate fixture-level verification from integrated-environment
> and production evidence. The M1 exit gate closed on 2026-09-09 with local
> staging evidence (tag `v0.1.0-m1`); remaining Partial/Open rows track M2 pilot
> and production gaps.

## Status definitions

| Status | Meaning |
| --- | --- |
| Verified | An executable automated test directly covers the criterion |
| Partial | Core behavior is tested, but one or more required integrations or outcomes are absent |
| Open | The required product capability or evidence does not exist yet |

## Acceptance criteria

| Roadmap scenario | Status | Current evidence | Remaining evidence |
| --- | --- | --- | --- |
| Repeated scanner import | Partial | `tests/integrations/test_defectdojo_bridge.py::test_defectdojo_replay_is_idempotent`; `tests/e2e/test_defectdojo_to_closed_case.py`; *2026-09-12: 24 real verified DefectDojo findings were re-enqueued and drained with no new snapshots or pending evidence outbox events; an explicitly simulated finding then exercised one confirmed exposure, one case, and one Jira projection under replay (see [staging evidence](operations/integrated-staging.md))* | Demonstrate a real report reimport that also exercises an externally delivered ticket projection |
| KEV escalation | Verified | `tests/risk/test_kev_escalation.py::test_kev_critical_internet_asset_selects_p0_policy`; explainability tests in `test_policy_simulation.py` | Repeat against a configured KEV source in integrated staging |
| SBOM match | Partial (target verified in staging) | CycloneDX/SPDX parser tests; `tests/matching/test_purl_range_match.py::test_purl_in_osv_range_creates_deterministic_exposure`; `tests/workflows/test_exposure_orchestration.py::test_m2_e2e_purl_match_creates_one_host_bound_active_finding_and_replays_cleanly`; *2026-09-13: authenticated host inventory plus host-bound `pkg:npm/jquery@3.3.9` made a real OSV request and persisted the GHSA/CVE alias, PURL range, active exposure, case, and replay-safe SBOM identity — see [staging evidence](operations/integrated-staging.md)* | Revise `M2-E2E-MATCH-001` total-count assertions to target `GHSA-6c3j-c64m-qhgq`: the current live OSV response also returns two other jQuery advisories, including on `3.4.0`; no target-CVE false positive occurred |
| Ambiguous mapping | Verified | `tests/matching/test_candidate_cpe_match.py::test_cpe_name_only_is_candidate_not_case`; asset reconciliation tests; *2026-09-09: candidate review API and console shipped (`tests/api/test_exposure_review.py`, `CandidateReviewView.vue`)* | Demonstrate operator review decisions through the candidate review API/console in integrated staging |
| Risk acceptance | Verified | `tests/cases/test_risk_acceptance_expiry.py`; `tests/cases/test_review_feedback.py::test_self_approval_rejected`; `tests/cases/test_review_feedback.py::test_authenticated_approval_records_claim_actor_and_changes_case_state`; `tests/api/test_authorization.py::test_risk_approver_approves_another_principal_request` | Demonstrate authenticated approval claims against a configured IdP in integrated staging |
| Verification | Verified | `tests/cases/test_verification_coverage.py` covers incomplete, failed, Wazuh, and manual evidence | Demonstrate real Wazuh/scanner observations with recorded coverage |
| Reopen | Verified | `tests/cases/test_state_machine.py::test_new_confirmed_evidence_reopens_closed_case`; expiry test | Demonstrate new real scanner evidence against an existing closed case |
| Source outage | Partial | KEV, EPSS, OSV, and Vulnerability-Lookup contract tests preserve state and mark stale/degraded; *2026-09-09: source-health API shipped (`tests/api/test_source_health.py`), polling adapters write cursor/health checkpoints, and `SourceHealthView.vue` exposes freshness/degraded status to operators* | Prove source-health status is visible to operators in integrated staging (UI walkthrough evidence still open) |
| Replay | Partial | Source snapshot, SBOM, DefectDojo, and Wazuh idempotency tests; *2026-09-12: real DefectDojo API replay of 24 findings drained to queue depth 0 without creating snapshots or pending evidence events; an explicit simulated upstream finding retained exactly 1 snapshot, 1 confirmed exposure, 1 case, and 1 Jira projection after replay* | Add cold cursor recovery and external projection deduplication evidence |
| Access | Verified in sandbox | OIDC/RBAC covers console and API routes; *2026-09-12: local Keycloak signed an explicit `evidence:raw:read` permission; anonymous/raw-unprivileged/authorized/cross-org reads returned 401/403/200/404, and the authorized bytes matched their stored SHA-256* | Repeat with the enterprise production IdP before production certification |
| OIDC authentication boundary | Verified | `tests/auth/test_oidc.py::test_valid_rsa_access_token_returns_verified_claims`; `tests/auth/test_oidc.py::test_registered_issuer_and_audience_are_checked`; `tests/auth/test_oidc.py::test_expired_token_is_rejected_using_injected_clock`; `tests/auth/test_oidc.py::test_unknown_kid_refreshes_jwks_once_then_fails_closed`; `tests/api/test_authentication.py::test_missing_bearer_token_returns_problem_details_401`; `tests/api/test_authentication.py::test_expired_bearer_token_returns_safe_invalid_token`; `tests/api/test_authentication.py::test_oidc_configuration_is_required_outside_explicit_test_bypass`; `tests/auth/test_production_idp_config.py`; `frontend/e2e/cases.spec.ts::OIDC login authenticates the console`; `frontend/e2e/cases.spec.ts::expired access tokens are rejected by the API and login callback`. *2026-09-08: password-grant tokens from a configured Keycloak sandbox verified by the API — see [the staging evidence log](operations/integrated-staging.md)* | Demonstrate a real configured production/staging IdP; scaffolding templates ship in [production IdP integration](operations/production-idp-integration.md) without claiming live certification |
| Organization RBAC | Verified | `tests/api/test_authorization.py::test_all_business_routes_have_literal_principal_status_matrix`; `tests/api/test_authorization.py::test_cross_org_resource_is_hidden_before_capability_and_validation`; `tests/api/test_authorization.py::test_viewer_reads_cases_but_cannot_create_or_transition`; `tests/api/test_authorization.py::test_owner_can_create_transition_request_risk_and_submit_verification`; `tests/api/test_authorization.py::test_service_scope_is_limited_to_named_sbom_capability`; `frontend/e2e/cases.spec.ts::auditor can read a case but cannot mutate it`; `frontend/e2e/cases.spec.ts::owner can perform a permitted transition`; `frontend/e2e/cases.spec.ts::cross-organization access is denied without disclosing the case`. *2026-09-08: owner/cross-org/auditor/unauthenticated matrix demonstrated with Keycloak-signed organization and role claims — see [the staging evidence log](operations/integrated-staging.md)* | Demonstrate organization claims and role mapping with the configured IdP in integrated staging |

## MVP scope coverage

| Must-have area | Status | Notes |
| --- | --- | --- |
| Organization and asset identity | Partial | Organization IDs and asset reconciliation exist; *2026-09-09: CSV/CMDB asset import shipped (hostname-alias reconciliation, create-or-update, collision skip)*; team/service ownership APIs remain open |
| CSV/CMDB and Wazuh observations | Partial | Wazuh bridge exists; *2026-09-09: CSV/CMDB asset import API shipped (`tests/api/test_asset_import.py`)*; team/service ownership APIs remain open |
| CycloneDX/SPDX ingestion | Verified in sandbox | API, parser, hashing, and idempotency tests exist. *2026-09-13: real authenticated M2 inputs bound each component occurrence to its declared existing hostname; duplicate byte-identical upload returned the same SBOM ID — see [the staging evidence log](operations/integrated-staging.md)* |
| Intelligence adapters | Partial (OSV verified in staging) | KEV, EPSS, OSV, and Vulnerability-Lookup contract tests exist. *2026-09-13: live OSV lookup persisted the GHSA, CVE alias, and PURL range needed by M2; PostgreSQL foreign-key ordering is regression-tested* | Demonstrate the remaining adapter set against their intended integrated sources |
| DefectDojo bridge | Verified in fixtures | Mapping, replay, conflict, and missing-evidence behavior are tested |
| Exposure generation/candidate queue | Partial (OSV deterministic path verified) | Matching behavior and orchestration exist; *2026-09-13: live `POST /v1/query` for the M2 jQuery PURL created deterministic exposures and cases with asset/component/PURL/range evidence, and replay kept the logical target exposure/case single.* Candidate review API and console remain shipped. | Demonstrate this through a shared adopter staging environment and resolve the case's stale unqualified total-finding assertions |
| Transparent risk policy | Verified in fixtures | Version, simulation, KEV escalation, and factors are tested |
| Case/SLA/audit/notifications | Partial | Workflow, SLA, audit, and outbox writes exist; *2026-09-12: an explicitly simulated DefectDojo Jira key was retained on a case created by the live queue/orchestrator path and remained single under replay.* Notification and real external-ticket delivery are open |
| Risk acceptance | Verified in fixtures | Domain behavior, separation of request/approval, and authenticated approval provenance are tested; integrated IdP evidence remains open |
| Verification and reopen | Verified in fixtures | Conservative closure and reopen behavior are tested |
| Source health and coverage gaps | Partial | Adapter status models exist; *2026-09-09: source-health API shipped (freshness + degraded flags), product-level polling adapters write cursor/health checkpoints, and `SourceHealthView.vue` exposes operator visibility*; integrated staging proof that operators can act on degraded-source alerts remains open |
| Secure self-hosted deployment | Partial | Compose, Helm, CI, SBOM, scan, Docker smoke, fail-closed OIDC configuration, and production IdP scaffold templates exist; live production certification remains open |

## Evidence required to close M1

- [x] OIDC/service authentication and organization-scoped RBAC tests pass; exact evidence is listed above.
- [x] The full fixture suite is mapped to this matrix without unsupported
  claims. *(Rows carry dated evidence notes; fixture-level rows are labeled
  "Verified in fixtures" rather than claimed as integrated evidence.)*
- [x] A non-production environment connects to configured sandbox instances of
  Vulnerability-Lookup, DefectDojo, and Wazuh.
  - *2026-09-08:* Local sandbox bring-up completed for DefectDojo, Wazuh
    (manager), and Keycloak per
    [the staging runbook](operations/integrated-staging.md); DefectDojo
    reimport and OIDC/RBAC demonstrations are recorded in its evidence log.
  - *2026-09-09:* Vulnerability-Lookup sandbox deployed and healthy (official
    compose, first-start source import in progress; API smoke deferred until
    the web server binds). A shared team environment remains a roadmap item;
    the local topology is the current non-production environment.
- [x] Source outage, cursor recovery, and replay are demonstrated and retained
  as dated evidence.
  - *2026-09-09:* OSV outage simulated via dead proxy — event deferred, not
    delivered, exposures unchanged (no silent downgrade); poison path logged.
    Outbox cursor recovery: a delivered event reset and replayed — same 14
    exposures, zero duplicate keys or case links. See
    [the staging evidence log](operations/integrated-staging.md).
- [x] Backup/restore and outbox replay commands are executed against the actual
  supported deployment topology. *(2026-09-09: local staging topology —
  pg_dump/restore drill with identical row counts; object-store digest check
  against the local backing store; moto-backed MinIO/S3 put/get/digest tests and
  host-staging `OBJECT_STORAGE_*` overlay shipped. A certified production
  topology drill remains open — see CHANGELOG known limitations.)*
- [x] The release commit has successful CI and Security workflow links.
  *(2026-09-09: tag `v0.1.0-m1` = commit 8b168df; CI run 34348813538 and
  Security run 34348813517 both successful.)*
- [x] Known limitations and operator safeguards are reviewed for the release.
  *(2026-09-09: CHANGELOG known limitations updated with the orchestration
  slice, replay-drill scope, and intel-persistence gaps.)*

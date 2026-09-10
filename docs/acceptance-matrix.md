# MVP Acceptance Matrix

> **Status date:** 2026-09-10
> **Baseline:** `main` at `0de66ef` (post-`v0.1.0-m1`)
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
| Repeated scanner import | Partial | `tests/integrations/test_defectdojo_bridge.py::test_defectdojo_replay_is_idempotent`; `tests/e2e/test_defectdojo_to_closed_case.py` | Demonstrate real DefectDojo reimport and prove external-ticket/outbox deduplication |
| KEV escalation | Verified | `tests/risk/test_kev_escalation.py::test_kev_critical_internet_asset_selects_p0_policy`; explainability tests in `test_policy_simulation.py` | Repeat against a configured KEV source in integrated staging |
| SBOM match | Verified | CycloneDX/SPDX parser tests; `tests/matching/test_purl_range_match.py::test_purl_in_osv_range_creates_deterministic_exposure` | Demonstrate an uploaded SBOM through asynchronous evaluation in integrated staging |
| Ambiguous mapping | Verified | `tests/matching/test_candidate_cpe_match.py::test_cpe_name_only_is_candidate_not_case`; asset reconciliation tests; *2026-09-09: candidate review API and console shipped (`tests/api/test_exposure_review.py`, `CandidateReviewView.vue`)* | Demonstrate operator review decisions through the candidate review API/console in integrated staging |
| Risk acceptance | Verified | `tests/cases/test_risk_acceptance_expiry.py`; `tests/cases/test_review_feedback.py::test_self_approval_rejected`; `tests/cases/test_review_feedback.py::test_authenticated_approval_records_claim_actor_and_changes_case_state`; `tests/api/test_authorization.py::test_risk_approver_approves_another_principal_request` | Demonstrate authenticated approval claims against a configured IdP in integrated staging |
| Verification | Verified | `tests/cases/test_verification_coverage.py` covers incomplete, failed, Wazuh, and manual evidence | Demonstrate real Wazuh/scanner observations with recorded coverage |
| Reopen | Verified | `tests/cases/test_state_machine.py::test_new_confirmed_evidence_reopens_closed_case`; expiry test | Demonstrate new real scanner evidence against an existing closed case |
| Source outage | Partial | KEV, EPSS, OSV, and Vulnerability-Lookup contract tests preserve state and mark stale/degraded; *2026-09-09: source-health API shipped (`tests/api/test_source_health.py`), polling adapters write cursor/health checkpoints, and `SourceHealthView.vue` exposes freshness/degraded status to operators* | Prove source-health status is visible to operators in integrated staging (UI walkthrough evidence still open) |
| Replay | Partial | Source snapshot, SBOM, DefectDojo, and Wazuh idempotency tests | Add durable cursor recovery, external projection deduplication, and replay drill evidence |
| Access | Partial | Implemented API and console access is covered by the OIDC and RBAC rows below, including the Playwright owner/auditor/cross-org flows | Add raw-evidence authorization when that resource is implemented and demonstrate access with a configured IdP in integrated staging |
| OIDC authentication boundary | Verified | `tests/auth/test_oidc.py::test_valid_rsa_access_token_returns_verified_claims`; `tests/auth/test_oidc.py::test_registered_issuer_and_audience_are_checked`; `tests/auth/test_oidc.py::test_expired_token_is_rejected_using_injected_clock`; `tests/auth/test_oidc.py::test_unknown_kid_refreshes_jwks_once_then_fails_closed`; `tests/api/test_authentication.py::test_missing_bearer_token_returns_problem_details_401`; `tests/api/test_authentication.py::test_expired_bearer_token_returns_safe_invalid_token`; `tests/api/test_authentication.py::test_oidc_configuration_is_required_outside_explicit_test_bypass`; `frontend/e2e/cases.spec.ts::OIDC login authenticates the console`; `frontend/e2e/cases.spec.ts::expired access tokens are rejected by the API and login callback`. *2026-09-08: password-grant tokens from a configured Keycloak sandbox verified by the API — see [the staging evidence log](operations/integrated-staging.md)* | Demonstrate a real configured production/staging IdP; the checked-in issuer is test-only, and the Keycloak sandbox is local, not the adopter IdP |
| Organization RBAC | Verified | `tests/api/test_authorization.py::test_all_business_routes_have_literal_principal_status_matrix`; `tests/api/test_authorization.py::test_cross_org_resource_is_hidden_before_capability_and_validation`; `tests/api/test_authorization.py::test_viewer_reads_cases_but_cannot_create_or_transition`; `tests/api/test_authorization.py::test_owner_can_create_transition_request_risk_and_submit_verification`; `tests/api/test_authorization.py::test_service_scope_is_limited_to_named_sbom_capability`; `frontend/e2e/cases.spec.ts::auditor can read a case but cannot mutate it`; `frontend/e2e/cases.spec.ts::owner can perform a permitted transition`; `frontend/e2e/cases.spec.ts::cross-organization access is denied without disclosing the case`. *2026-09-08: owner/cross-org/auditor/unauthenticated matrix demonstrated with Keycloak-signed organization and role claims — see [the staging evidence log](operations/integrated-staging.md)* | Demonstrate organization claims and role mapping with the configured IdP in integrated staging |

## MVP scope coverage

| Must-have area | Status | Notes |
| --- | --- | --- |
| Organization and asset identity | Partial | Organization IDs and asset reconciliation exist; *2026-09-09: CSV/CMDB asset import shipped (hostname-alias reconciliation, create-or-update, collision skip)*; team/service ownership APIs remain open |
| CSV/CMDB and Wazuh observations | Partial | Wazuh bridge exists; *2026-09-09: CSV/CMDB asset import API shipped (`tests/api/test_asset_import.py`)*; team/service ownership APIs remain open |
| CycloneDX/SPDX ingestion | Verified | API, parser, hashing, persistence, and idempotency tests exist. *2026-09-08: real authenticated submission through the staging Keycloak/API path recorded — see [the staging evidence log](operations/integrated-staging.md)* |
| Intelligence adapters | Verified in fixtures | KEV, EPSS, OSV, and Vulnerability-Lookup contract tests exist; staging evidence remains open |
| DefectDojo bridge | Verified in fixtures | Mapping, replay, conflict, and missing-evidence behavior are tested |
| Exposure generation/candidate queue | Partial | Matching behavior and orchestration exist; *2026-09-09: outbox orchestrator consumed a real `vulnops.sbom.processed.v1` event, queried the real api.osv.dev, and wrote 14 exposures to the `exposures` table (see [the staging evidence log](operations/integrated-staging.md)); candidate review API and console shipped (`tests/api/test_exposure_review.py`, `CandidateReviewView.vue`)*. Against the live OSV API the outcome is candidate-only: `/v1/querybatch` returns `{id, modified}` stubs without `affected` ranges (the single `POST /v1/query` does return full ranges), and version-qualified purls sent together with a `version` param are rejected with 400 — so deterministic matching and auto case creation remain demonstrated in fixtures only |
| Transparent risk policy | Verified in fixtures | Version, simulation, KEV escalation, and factors are tested |
| Case/SLA/audit/notifications | Partial | Workflow, SLA, audit, and outbox writes exist; notification and external-ticket delivery are open |
| Risk acceptance | Verified in fixtures | Domain behavior, separation of request/approval, and authenticated approval provenance are tested; integrated IdP evidence remains open |
| Verification and reopen | Verified in fixtures | Conservative closure and reopen behavior are tested |
| Source health and coverage gaps | Partial | Adapter status models exist; *2026-09-09: source-health API shipped (freshness + degraded flags), product-level polling adapters write cursor/health checkpoints, and `SourceHealthView.vue` exposes operator visibility*; integrated staging proof that operators can act on degraded-source alerts remains open |
| Secure self-hosted deployment | Partial | Compose, Helm, CI, SBOM, scan, Docker smoke, and fail-closed OIDC configuration exist; production certification remains open |

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
  against the local backing store. A certified production topology with
  MinIO/S3 remains open — see CHANGELOG known limitations.)*
- [x] The release commit has successful CI and Security workflow links.
  *(2026-09-09: tag `v0.1.0-m1` = commit 8b168df; CI run 34348813538 and
  Security run 34348813517 both successful.)*
- [x] Known limitations and operator safeguards are reviewed for the release.
  *(2026-09-09: CHANGELOG known limitations updated with the orchestration
  slice, replay-drill scope, and intel-persistence gaps.)*

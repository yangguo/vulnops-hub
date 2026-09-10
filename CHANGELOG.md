# Changelog

This project follows Keep a Changelog conventions. Until the first tagged
release, entries describe the current `main` technical preview and may contain
intentional contract changes.

## Unreleased

### Added

- Vue 3 remediation operations console with dashboard, case list/detail,
  lifecycle actions, risk decisions, verification, and SBOM submission.
- Paginated and filtered case reads plus risk-decision and verification history
  endpoints.
- FastAPI SPA serving, multi-stage container build, Playwright smoke test, and
  frontend CI gates.
- A loopback-only OIDC test issuer and Playwright enforcement flows for login,
  auditor read-only access, owner transitions, token expiry, and cross-org denial.
- Node.js 22.22.2 and pnpm 9.15.0 development baseline.
- As-built development guide, MVP acceptance matrix, and OIDC/RBAC next-slice
  design and implementation plan.
- Outbox orchestration worker (`orchestrator` compose service) that consumes
  evidence events, queries OSV for advisories, evaluates deterministic
  matches, upserts exposures with policy-derived priority, and auto-creates
  remediation cases with SLA clocks for confirmed/deterministic matches
  (`CASE_AUTO_CREATE_ENABLED` kill switch; candidates queue for review).
- Profile-isolated staging sandbox compose for DefectDojo, Wazuh (manager),
  and a configured Keycloak realm with organization/role claims, plus a
  sandbox fetch script that stands in for product-level polling adapters.
- Integrated-staging runbook with dated evidence: OIDC/RBAC against the
  configured IdP, real DefectDojo reimport idempotency, Wazuh package
  ingestion, backup/restore and outbox replay drills, source-outage handling,
  and the deterministic SBOM→match→case loop against the live OSV API.
- M2 operational slice: product-level DefectDojo/Wazuh polling adapters
  (cursor/checkpoint/health, `poller` compose service), source-health API,
  CSV/CMDB asset import with hostname-alias reconciliation, candidate
  exposure review API with audit trail, Jira issue-key link-back for
  scanner-confirmed auto-cases, and VEX statements via Vulnerability-Lookup
  feeding match policy (ADR 0002).
- Greenbone/OpenVAS scanner provenance via DefectDojo: Greenbone-shaped
  findings retain normalized scanner, scan-type, and test-type metadata through
  the existing DefectDojo poller → bridge → orchestration path; no native
  Greenbone bridge is added.
- Console source-health page (freshness badges, degraded-source alert) and
  candidate review page (decision dialog writing audited reasons), with
  navigation gated by capability.
- BusinessService create/list/get API, CSV asset owner/service linkage,
  asset/service-aware case owner resolution, and audited P0/P1 escalation for
  cases that remain unassigned.

### Changed

- Project status is described as an M1 technical preview rather than a complete
  production-ready MVP.
- API business routes enforce configured OIDC bearer authentication,
  organization-scoped RBAC, and server-derived workflow actors; the console's
  capability-aware controls remain a UX layer over that server authority.
- CI records automated OIDC/RBAC verification with a test issuer. This is not
  evidence of integration with a production identity provider.
- Case-list ordering is deterministic and preserves the nullable `exposures`
  response contract.

### Fixed

- Normalized nested Problem Details errors in the frontend.
- Improved optimistic-lock conflict handling and lifecycle action feedback.
- Granted the Security workflow the permission required to upload SARIF and
  upgraded the upload action to v4.
- OSV adapter queries now use per-component `/v1/query` with version-stripped
  purls (the batch endpoint returned range-less stubs and rejected
  version-qualified purls), restoring deterministic matching against the
  live API; orchestrator retries defer to the next poll instead of burning
  attempts, and poison events are logged as dead-lettered.

### Known limitations

- Production IdP integration, production certification, shared adopter
  integrated-staging evidence, and raw-evidence authorization remain open.
- External-ticket and notification delivery are delegated to DefectDojo's
  Jira integration for scanner-confirmed cases (ADR 0002); ServiceNow,
  case-level projection, and broader notification channels remain open.
- Wazuh package observations without purls do not produce deterministic
  matches; name-only CVE correlation stays in the candidate review queue
  (purl derivation from Wazuh package metadata remains open).
- The production frontend build reports large chunk warnings for Element Plus
  and ECharts bundles.
- Backup/restore and outbox replay have been rehearsed against the local
  staging topology (see the integrated-staging evidence log); a certified
  production topology drill with MinIO/S3 object storage remains open.
- Intel-table persistence (`Vulnerability`/`AffectedRange` upserts) and KEV
  catalog periodic refresh are unimplemented; enrichment is on-demand only.

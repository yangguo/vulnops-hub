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
- Node.js 24.21.0 and pnpm 9.15.0 development baseline.
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
- M2 Wazuh purl derivation: best-effort Package URLs from syscollector
  `format`/name/version with agent-OS deb namespace (never package vendor) and
  RPM vendor when mappable; orchestration binds OSV results to the Wazuh CVE
  before auto-casing. APK/RPM rows may still land as matcher candidates when
  the ecosystem is unsupported.
- Greenbone/OpenVAS provenance support via DefectDojo: the poller and sandbox
  fetch request `related_fields=true`, and fixture-covered findings retain
  normalized scanner, scan-type, and test-type metadata through the existing
  poller → bridge → orchestration path. Live Greenbone/DefectDojo verification
  remains pending; no native Greenbone bridge is added.
- Authenticated local staging workflow for a verified DefectDojo/OpenVAS
  finding: an explicit staging-only loopback OIDC opt-in supports the
  host-run API path, and coverage proves asset/SBOM setup, scanner-confirmed
  exposure/case creation, replay safety, and DefectDojo Jira-key recording.
- Console source-health page (freshness badges, degraded-source alert) and
  candidate review page (decision dialog writing audited reasons), with
  navigation gated by capability.
- BusinessService create/list/get API, CSV asset owner/service linkage,
  asset/service-aware case owner resolution, and audited P0/P1 escalation for
  cases that remain unassigned.
- Raw-evidence API authorization: SBOM and source-snapshot metadata no longer
  expose storage URIs without `evidence:raw:read`; authorized `/raw` downloads
  are org-scoped with `404`/`403` behavior aligned to existing OIDC/RBAC.
- S3/MinIO object storage for SBOM raw evidence: boto3 client wiring,
  host-staging env overlay, moto-backed tests, `scripts/object_storage_smoke.py`,
  and [object storage operations guide](docs/operations/object-storage.md).
- Intel-table persistence for OSV/KEV (and optional Vulnerability-Lookup)
  enrichment: idempotent upserts into `Vulnerability`, `AffectedRange`, aliases,
  and `AdvisoryAssertion`; KEV catalog refresh on orchestrator startup, periodic
  orchestrator refresh (`KEV_REFRESH_INTERVAL_SECONDS`), and
  `vulnops.workers.intel_refresh` worker entrypoint with source-health
  checkpoints.
- Production IdP integration scaffolding: HTTPS issuer/audience/JWKS requirements,
  deploy and Helm example templates with safe defaults, frontend production OIDC
  placeholders, and additional fail-closed startup checks for
  `ENVIRONMENT=production` (no test bypass, no loopback opt-in, HTTPS issuer).

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

- Upgraded Vitest to 4.1.11 and forced Redocly's pinned `js-yaml` dependency
  to 4.3.2, resolving the active frontend development-tool advisories.
- Upgraded Security workflow actions to their Node 24-compatible majors.
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

- Live production IdP certification and shared adopter integrated-staging
  evidence remain open; scaffolding docs/templates ship without claiming a
  certified enterprise IdP integration.
- Live OpenVAS ingress/replay and the authenticated exposure/case contract are
  verified separately in local staging. A live authenticated operator run and
  shared adopter environment still require a TLS-published issuer and trusted CA.
- External-ticket and notification delivery are delegated to DefectDojo's
  Jira integration for scanner-confirmed cases (ADR 0002); ServiceNow,
  case-level projection, and broader notification channels remain open.
- Wazuh purl derivation is best-effort only: deb rows need agent OS distro
  hints, RPM without a recognizable vendor stays skipped, non-Linux formats and
  unsupported matcher ecosystems (including many APK/RPM derivations) still
  produce candidate exposures rather than guessed identities.
- The production frontend build reports large chunk warnings for Element Plus
  and ECharts bundles.
- Backup/restore and outbox replay have been rehearsed against the local
  staging topology (see the integrated-staging evidence log). MinIO/S3 put/get
  is implemented and CI-tested with moto; a certified production topology drill
  (versioned bucket sync + PITR + live digest audit at scale) remains open.
- EPSS bulk persistence and automatic clearing of CVEs removed from the CISA
  KEV catalog remain open; OSV matching still uses live API queries (intel
  tables are a cache/fallback, not the sole source of truth).

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

### Known limitations

- Production IdP integration, production certification, first-adopter
  integrated-staging evidence, and raw-evidence authorization remain open.
- Source-health and coverage-gap APIs/UI, CSV/CMDB import, external-ticket and
  notification delivery, and integrated-staging evidence remain open.
- The production frontend build reports large chunk warnings for Element Plus
  and ECharts bundles.
- Backup/restore and outbox replay documentation is a target procedure and has
  not yet been rehearsed against a certified production topology.

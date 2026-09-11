# Node 24 and Vitest Security Baseline Design

## Context

Dependabot reports the Vitest path-traversal advisory against `vitest` and
`@vitest/mocker` 3.2.7. The first fixed v4 release is 4.1.11. Dependabot cannot
prepare that update because the frontend currently restricts Node to 22.x,
while the updater executes with Node 24.21.0. A fresh local `pnpm audit` also
reports `js-yaml` 4.3.1 through Redocly; that package pins the vulnerable patch
instead of declaring a compatible range.

## Decision

- Move the supported frontend runtime from Node 22 to Node 24.
- Keep pnpm at 9.15.0 to avoid combining package-manager migration risk with
  the security fix.
- Upgrade Vitest to 4.1.11, the smallest fixed stable release, instead of
  adopting Vitest 5 in the same change.
- Apply a dependency-scoped pnpm override from Redocly's pinned `js-yaml`
  4.3.1 to the compatible patched 4.3.2 release.
- Apply the runtime consistently in package engines, CI, the container build,
  and current developer documentation.
- Move the Security workflow's checkout, Python setup, and gitleaks actions to
  their Node 24-compatible majors so the workflow no longer relies on the
  runner's deprecated Node 20 compatibility path.

## Alternatives considered

1. Broaden engines to accept Node 24 but continue testing and shipping Node 22.
   This would unblock Dependabot but leave different declared and exercised
   runtimes, so it is rejected.
2. Upgrade directly to Vitest 5. This also fixes the advisory but introduces a
   second major-version migration and different mock-reset behavior, so it is
   deferred.
3. Override the vulnerable transitive package. This would separate Vitest from
   its internal package versions and is rejected as a brittle partial fix.

## Verification

The change is complete only when the lockfile contains no vulnerable Vitest
3.2.7 packages, `pnpm audit` is clean, lint/typecheck/unit tests/build pass on
Node 24, Playwright E2E passes, the Docker image builds, and GitHub CI/Security
pass on the exact pushed commit.

# Node 24 and Vitest Security Baseline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove the active frontend toolchain security alerts and restore successful Dependabot updates with one consistent Node 24 frontend runtime.

**Architecture:** Keep the application unchanged. Update only the frontend toolchain contract, generated lockfile, CI/container runtime pins, and current documentation; verify the existing behavioral suite against the new test runner.

**Tech Stack:** Node.js 24, pnpm 9.15.0, Vitest 4.1.11, Vue 3, Vite 6, GitHub Actions, Docker.

### Task 1: Record the failing security baseline

**Files:**
- Inspect: `frontend/package.json`
- Inspect: `frontend/pnpm-lock.yaml`

1. Run `pnpm audit` using the supported Node 22 runtime.
2. Confirm the audit identifies `vitest`/`@vitest/mocker` 3.2.7 and Redocly's pinned `js-yaml` 4.3.1.
3. Preserve the GitHub Dependabot failure showing the Node 22 engine constraint rejects its Node 24 updater.

### Task 2: Upgrade the runtime and test runner

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/pnpm-lock.yaml`
- Modify: `.github/workflows/ci.yml`
- Modify: `Dockerfile`

1. Change the frontend Node engine to Node 24.x while retaining pnpm 9.x.
2. Pin Vitest to `^4.1.11`.
3. Add a scoped override for Redocly's `js-yaml` dependency at 4.3.2.
4. Regenerate the lockfile with Node 24 and pnpm 9.15.0.
5. Change both CI Node pins and the container frontend stage to Node 24.
6. Run `pnpm audit` and confirm zero known vulnerabilities.

### Task 3: Synchronize current documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/development.md`
- Modify: `CHANGELOG.md`

1. Replace the current Node 22 development baseline with Node 24.
2. Record the Vitest security remediation in the changelog.
3. Search current, non-historical files for surviving Node 22 instructions.

### Task 4: Verify and publish

**Files:**
- Verify: all files changed by Tasks 1-3

1. Run frontend lint, typecheck, unit tests, and production build on Node 24.
2. Run Playwright E2E and build the Docker image.
3. Review the diff and confirm no application behavior changed.
4. Commit and push `codex/node24-vitest-security`.
5. Confirm GitHub CI and Security succeed on the exact commit.

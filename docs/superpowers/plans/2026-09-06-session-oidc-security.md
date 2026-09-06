# Session and OIDC Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close B1, Finding 1, and Finding 2 from the Level 3 re-review while preserving the checked-in loopback Playwright flow.

**Architecture:** The auth Pinia store will expose one unauthenticated transition that clears the organization and SBOM stores. SBOM writes will be generation-gated so responses from a pre-cleanup request cannot repopulate state. The OIDC verifier will accept HTTPS by default and an explicit loopback-only HTTP exception for development/test settings; the E2E issuer will enforce loopback binding and exact browser redirect sinks.

**Tech Stack:** Vue 3, Pinia, TypeScript, Vitest, Python 3.12, pytest, httpx, PyJWT, `ipaddress`, and the existing Playwright test issuer.

**Spec:** `docs/superpowers/specs/2026-09-06-session-oidc-security-design.md`

## Global Constraints

- Do not persist OIDC access or refresh tokens in browser storage.
- Clear `vulnops.org` and `vulnops.sbom-history` on every transition to unauthenticated state.
- Allow HTTP OIDC URLs only for strict loopback hosts in explicit development/test mode.
- Reject an HTTPS issuer whose discovery advertises an HTTP JWKS URL.
- Keep the E2E issuer bound to loopback and preserve the existing `127.0.0.1` CI command.
- Do not open or merge a pull request.

---

### Task 1: Frontend state stores and cleanup boundary

**Files:**
- Create: `frontend/src/stores/sbomHistory.ts`
- Create: `frontend/src/stores/sbomHistory.test.ts`
- Modify: `frontend/src/auth/sessionCleanup.ts`

**Interfaces:**
- Produces `useSbomHistoryStore`, `SBOM_HISTORY_STORAGE_KEY`, `SbomHistoryEntry`, `generation`, `clear()`, and `record(entry, generation)`.
- `clearUserBoundBrowserState()` clears both the org and SBOM stores and retains its storage fallback for tests without active Pinia.

- [ ] Write tests proving persisted history loads, `clear()` resets live and persisted state, and `record()` rejects stale generations without writing.
- [ ] Run `cd frontend && pnpm exec vitest run src/stores/sbomHistory.test.ts`; expect the new store import/API to fail before implementation.
- [ ] Implement the minimal Pinia store with safe JSON loading, generation increment on clear, and generation-checked persistence.
- [ ] Update `sessionCleanup.ts` to call the SBOM store alongside `useOrgStore()`.
- [ ] Rerun the focused store tests and then commit only this task if it is green.

### Task 2: Centralize frontend unauthenticated transitions

**Files:**
- Modify: `frontend/src/stores/auth.ts`
- Modify: `frontend/src/stores/auth.test.ts`
- Modify: `frontend/src/App.vue`
- Create or modify: `frontend/src/App.test.ts`

**Interfaces:**
- `useAuthStore.clearUnauthenticatedSession(message?: string)` becomes the only auth action that nulls the user for session loss and invokes browser cleanup.
- `useAuthStore.installUser(user)` clears browser state before binding a callback identity and rejects expired identities through the central action.

- [ ] Add failing tests for null startup, expired startup, callback failure, `userUnloaded`, identity switch, and provider logout rejection; assert both storage keys and live stores are cleared.
- [ ] Run the focused auth/App tests and confirm each fails for the missing lifecycle behavior.
- [ ] Implement the central action, route all listed callers through it, and make `App.vue` catch logout rejection and replace the route with `/login`.
- [ ] Rerun focused frontend tests and verify existing router behavior remains intact.

### Task 3: Generation-gate SBOM view requests

**Files:**
- Modify: `frontend/src/views/SbomSubmitView.vue`
- Modify: `frontend/src/views/SbomSubmit.test.ts`

**Interfaces:**
- The view consumes `useSbomHistoryStore`; it does not read or write `vulnops.sbom-history` directly.
- A submit captures `historyStore.generation` and records only through `historyStore.record(entry, capturedGeneration)`.

- [ ] Add a deferred-request test that clears the SBOM store before resolving and asserts the stale response cannot update history or localStorage.
- [ ] Run the focused view test and confirm it fails because the view still owns a local history ref and writes directly.
- [ ] Replace the local ref/load/persistence logic with the Pinia store and gate result/history updates on the captured generation.
- [ ] Rerun the focused view tests.

### Task 4: Enforce secure OIDC issuer and JWKS URLs

**Files:**
- Modify: `src/vulnops/auth/oidc.py`
- Modify: `tests/auth/test_oidc.py`

**Interfaces:**
- `OIDCVerifier(..., allow_insecure_loopback: bool = False)` is strict by default.
- `OIDCVerifier.from_settings()` derives the explicit exception from `settings.environment in {"development", "test"}`.

- [ ] Add failing tests for remote HTTP constructor rejection, explicit loopback HTTP acceptance, remote HTTP discovered JWKS rejection, and HTTPS-to-HTTP JWKS downgrade rejection.
- [ ] Run those tests and confirm failures identify the permissive URL validation.
- [ ] Implement strict URL parsing with `ipaddress.ip_address(...).is_loopback`, enforce HTTPS by default, and keep HTTP exception limited to loopback plus explicit mode. Reject HTTP JWKS for an HTTPS issuer.
- [ ] Rerun the focused OIDC tests and the complete `tests/auth` suite.

### Task 5: Harden the E2E OIDC issuer

**Files:**
- Modify: `tests/e2e/oidc_test_issuer.py`
- Create: `tests/e2e/test_oidc_test_issuer.py`

**Interfaces:**
- The fixture exposes testable validation helpers for bind host, advertised issuer, and allowed browser redirect URIs.
- `main()` rejects non-loopback bind/issuer values before creating the server.

- [ ] Add failing tests for non-loopback bind host, non-loopback advertised issuer, accepted loopback values, and rejected authorization/logout redirect URIs.
- [ ] Run the focused issuer tests and confirm the current permissive fixture fails them.
- [ ] Implement loopback validation and exact Playwright redirect allowlists while preserving the existing default invocation.
- [ ] Rerun the focused issuer tests and the frontend E2E configuration smoke if dependencies are available.

### Task 6: Full verification and local handoff

**Files:**
- Inspect all changed files and Git history; no additional source files are expected.

- [ ] Run `cd frontend && pnpm test`.
- [ ] Run `uv run pytest tests/auth` and `uv run pytest tests/e2e/test_oidc_test_issuer.py`.
- [ ] Run frontend typecheck/lint if available and inspect the complete diff for surviving state or transport bypasses.
- [ ] Commit the three remediation areas with the requested clear subjects.
- [ ] Attempt `git push`; if it fails, retain local commits and report the exact result without opening a PR.

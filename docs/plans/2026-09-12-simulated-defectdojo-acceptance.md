# Simulated DefectDojo Acceptance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Reproducibly exercise the authenticated asset/SBOM, simulated DefectDojo finding, queue, ingestion, orchestration, confirmed exposure, remediation case, Jira projection, and replay-deduplication path without claiming that the fixture is a real scanner report.

**Architecture:** A checked-in, explicitly marked DefectDojo-shaped fixture is the only simulated boundary. A small CLI loads it, applies a caller-supplied stable finding ID, and enqueues it through the normal Valkey ingestion queue. The host API and existing workers continue to provide authentication, persistence, matching, case creation, and idempotency behavior unchanged.

**Tech Stack:** Python 3.13, FastAPI, SQLAlchemy/PostgreSQL, Valkey, Keycloak, pytest, DefectDojo-shaped JSON.

### Task 1: Define a safe, explicit simulated finding fixture

**Files:**
- Create: `tests/fixtures/defectdojo/simulated_acceptance_finding.json`
- Test: `tests/acceptance/test_simulated_defectdojo_acceptance.py`

1. Write a failing test that rejects a fixture without a `[SIMULATED ACCEPTANCE]` marker and requires host, PURL, version, verified status, CVE, and nested Jira key.
2. Run `uv run pytest tests/acceptance/test_simulated_defectdojo_acceptance.py -q`; verify it fails because the fixture/loader is absent.
3. Add the fixture with no real target, user, secret, or scan result; use the existing neutral `payments-api-3`/openssl acceptance identity.
4. Re-run the focused test and confirm it passes.

### Task 2: Add a queue-only simulation CLI

**Files:**
- Create: `scripts/simulated_defectdojo_acceptance.py`
- Test: `tests/acceptance/test_simulated_defectdojo_acceptance.py`

1. Add a failing test for a pure `build_job` function: it must clone the fixture, require a non-empty run ID, set a stable simulated finding ID, retain the marker, and produce the normal `defectdojo:<id>` idempotency key.
2. Run the focused test and verify the expected missing-import failure.
3. Implement the minimal loader/build function and CLI. Reuse `scripts.sandbox_fetch.enqueue`; do not add a new queue implementation or bypass the worker.
4. Re-run the focused test; then run `uv run ruff check scripts tests/acceptance`.

### Task 3: Execute and document the local acceptance drill

**Files:**
- Modify: `docs/operations/integrated-staging.md`
- Modify: `docs/acceptance-matrix.md`

1. Start the documented host API, ingestion worker, and orchestrator with Keycloak and MinIO enabled.
2. With `admin-demo`, create/update the fixture asset and submit a CycloneDX SBOM containing `pkg:deb/debian/openssl@3.0.2`.
3. Enqueue one fixture run and wait for a confirmed exposure and case with Jira key `VULN-77`; enqueue the same run again and prove no duplicate source snapshot, exposure, case, or external-ticket projection.
4. Record the command-independent results as `PASS (simulated upstream)` and keep the real OpenVAS ingress result distinct.

### Task 4: Verify and integrate

1. Run `uv run ruff check src scripts tests` and `uv run ruff format --check src scripts tests`.
2. Run `uv run pytest -q`, `docker compose config --quiet`, and the staging Compose configuration check.
3. Review the branch diff, commit, merge to `main`, push, and remove the temporary worktree/branch.

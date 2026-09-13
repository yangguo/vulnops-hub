# M2 E2E PURL Match Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the supplied `M2-E2E-MATCH-001` case repeatable: a host-bound CycloneDX component is matched through OSV PURL version ranges, while the fixed-version control and replay produce no duplicate active finding.

**Architecture:** Preserve the existing two-step inventory model. A CycloneDX document may declare an existing same-organization host with `metadata.properties` key `vulnops:asset.hostname`; SBOM ingestion resolves that exact hostname and writes the resulting `asset_id` onto each component occurrence. The orchestrator already uses occurrence identity, real OSV lookup, version-range evaluation, and idempotent exposure/case upserts, so no CVE is added to the input.

**Tech Stack:** FastAPI, SQLAlchemy, CycloneDX JSON, OSV API adapter, pytest, Docker Compose staging.

### Task 1: Specify and test hostname-to-asset binding

**Files:**
- Create: `tests/sbom/test_service.py`
- Modify: `src/vulnops/sbom/service.py`

**Step 1: Write the failing test**

Create a same-organization asset with hostname alias `m2-vulnerable-web-01`, ingest a CycloneDX SBOM containing `metadata.properties: [{"name": "vulnops:asset.hostname", "value": "m2-vulnerable-web-01"}]`, and assert its single `ComponentOccurrence.asset_id` equals that asset. Add a second test proving an unknown hostname creates no asset and leaves the occurrence unbound.

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/sbom/test_service.py -k asset_hostname -v`

Expected: FAIL because occurrences currently always receive a null `asset_id`.

**Step 3: Write minimal implementation**

Extract the named CycloneDX metadata property, resolve it through `AssetService.reconcile_alias("hostname", ...)` in the target organization, and pass the resolved ID to each occurrence. Do not create assets from SBOM metadata and do not bind ambiguous or cross-organization aliases.

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/sbom/test_service.py -k asset_hostname -v`

Expected: PASS.

**Step 5: Commit**

```bash
git add src/vulnops/sbom/service.py tests/sbom/test_service.py
git commit -m "feat(sbom): bind occurrences to declared asset hostname"
```

### Task 2: Add an executable M2 case fixture and acceptance test

**Files:**
- Create: `tests/fixtures/m2/e2e_purl_match_001.cdx.json`
- Modify: `tests/workflows/test_exposure_orchestration.py`

**Step 1: Write the failing test**

Build two host-bound occurrence scenarios from the case: `pkg:npm/jquery@3.3.9` and `pkg:npm/jquery@3.4.0`. Feed a recorded OSV representation of `GHSA-6c3j-c64m-qhgq` into the real matcher. Assert the vulnerable component creates exactly one active deterministic exposure and case with `CVE-2019-11358` retained as alias evidence; assert the fixed component produces no active exposure/case; replay the vulnerable event and assert no duplicate exposure, case, or match evidence.

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -k m2_e2e_purl_match -v`

Expected: FAIL because the named acceptance coverage does not yet exist.

**Step 3: Write minimal implementation**

Use the existing OSV adapter and matcher seams; do not add a special case for jquery or CVE data to the input. Retain the fixture as a CycloneDX document containing only component identity and host-binding metadata.

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/workflows/test_exposure_orchestration.py -k m2_e2e_purl_match -v`

Expected: PASS.

**Step 5: Commit**

```bash
git add tests/fixtures/m2/e2e_purl_match_001.cdx.json tests/workflows/test_exposure_orchestration.py
git commit -m "test(acceptance): cover M2 PURL version range case"
```

### Task 3: Run the supplied case against staging and record evidence

**Files:**
- Modify: `docs/operations/integrated-staging.md`
- Modify: `docs/acceptance-matrix.md`

**Step 1: Prepare controlled input**

Import `m2-vulnerable-web-01` and `m2-fixed-web-01` with their stated IPs, then submit separate CycloneDX SBOMs that contain no vulnerability identifiers and declare each hostname with `vulnops:asset.hostname`.

**Step 2: Execute and inspect**

Run the real orchestrator against OSV. Inspect persisted assets, component occurrences, exposures, cases, aliases/ranges, source snapshots, and outbox state. Replay the vulnerable SBOM input using the same content and inspect stable logical counts.

**Step 3: Record evidence precisely**

Document the exact live outcome for AC-01 through AC-08 and the negative control. State any unavailable external dependency or data mismatch as a failure/limitation; do not substitute fixture output for a live OSV response.

**Step 4: Verify full repository**

Run:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest -q
docker compose config --quiet
docker compose -f deploy/docker-compose.staging.yml --env-file deploy/.env.staging config --quiet
```

**Step 5: Commit**

```bash
git add docs/operations/integrated-staging.md docs/acceptance-matrix.md
git commit -m "docs: record M2 PURL acceptance evidence"
```

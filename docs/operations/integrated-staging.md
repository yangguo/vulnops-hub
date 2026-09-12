# Integrated Staging Runbook

> **Status:** Target procedure, first executed 2026-09. Each sandbox run that
> produces acceptance evidence must be recorded in
> [the evidence log](#evidence-log) with a date and the commit under test.
> Checklist semantics come from the
> [adapter onboarding template](adapter-onboarding.md).

Local staging provides sandbox instances of the external systems the M1 exit
gate names: DefectDojo, Wazuh, Vulnerability-Lookup, and a configured OIDC
identity provider. Sandboxes are for local evidence collection only — every
credential below is a sandbox default and must never be reused elsewhere.

## Topology

- Sandboxes are defined in `deploy/docker-compose.staging.yml`, one profile
  per stack, with their own volumes, and publish host ports only.
- The VulnOps worker/poller containers (from the root `docker-compose.yml`)
  can reach sandboxes through `http://host.docker.internal:<port>`, so the
  application compose file stays untouched. The authenticated workflow below
  runs the API on the host because the checked-in Keycloak profile publishes a
  loopback HTTP issuer.
- DefectDojo/Wazuh records enter the pipeline via the queue: the product-level
  poller (or `scripts/sandbox_fetch.py` for a direct sandbox run) → Valkey
  `vulnops:ingest` → ingestion worker → bridges. The poller checkpoints only
  after jobs are durably enqueued.
- Vulnerability-Lookup is launched from its own repository (it builds from
  source with its own kvrocks/valkey/postgres backing services).

## Prerequisites

- Docker Desktop with the WSL2 backend, disk image location on `D:\Docker`
  (see the project memory notes; C-drive space is scarce).
- The VulnOps stack running: `docker compose up -d` from the repo root. The
  one-shot `migrate` service runs `alembic` before API, poller, worker, or
  orchestrator services start; inspect `docker compose logs migrate` if the
  dependent services remain in `Created` state.
- Configure `OIDC_ISSUER_URL` and `OIDC_AUDIENCE` before expecting the API to
  become ready. The compose stack deliberately fails closed without them;
  do not enable the test authentication bypass for a staging demonstration.
- Copy credentials: `cp deploy/.env.staging.example deploy/.env.staging`.
- **TLS-intercepting networks (corporate MITM):** the product `Dockerfile`
  fails with `SELF_SIGNED_CERT_IN_CHAIN` inside build containers. The local
  workaround (git-ignored, not committed) is `deploy/Dockerfile.local` plus a
  `docker-compose.override.yml` that selects it, both injecting the corporate
  root CA via `NODE_EXTRA_CA_CERTS` / `PIP_CERT` / `update-ca-certificates`.
  See the evidence log entry dated 2026-09-08.

### Authenticated workflow topology

This slice uses the **host-run API/worker/poller path** for local staging. It
is the supported runnable path for the checked-in Keycloak profile:

1. Keycloak publishes `http://127.0.0.1:8082/realms/vulnops` on the host.
2. The API, ingestion worker, orchestrator, and poller run with `uv` on the
   host and use the host-published PostgreSQL, Valkey, and MinIO ports.
3. `ENVIRONMENT=staging` plus the explicit
   `OIDC_ALLOW_INSECURE_LOOPBACK=true` opt-in allows only that IP-loopback
   HTTP issuer. `AUTH_TEST_BYPASS_ENABLED` remains `false`.

This is not a general HTTP exception: `OIDCVerifier` still rejects
`host.docker.internal`, bridge addresses, and all other non-loopback HTTP
issuers, and production cannot enable the loopback opt-in. A containerized API
requires a TLS-published Keycloak issuer and a trusted CA; do not configure
`http://host.docker.internal:8082` as its issuer.

## Sandbox bring-up

### DefectDojo

```bash
docker compose -f deploy/docker-compose.staging.yml --env-file deploy/.env.staging \
  --profile defectdojo up -d
# First start pulls images and runs migrations; the initializer takes up to
# 3 minutes. Wait for it to exit successfully:
docker compose -f deploy/docker-compose.staging.yml logs -f dojo-initializer
```

API is on `http://localhost:8081` (nginx in front of uwsgi), admin login
`admin` / `${DOJO_ADMIN_PASSWORD}`.

To fetch findings with the script you need a REST API token: log into the
DefectDojo UI, open the user profile, and copy the **API Key**, or generate
one from the container (sandbox only):

```bash
docker exec deploy-dojo-uwsgi-1 python manage.py drf_create_token admin
```

Note: DefectDojo v2 API paths use underscores (`/api/v2/product_types/`,
not `product-types`). Creating demo findings requires the full hierarchy
(product type → product → engagement → test type → test → finding).

```bash
uv run python scripts/sandbox_fetch.py defectdojo \
  --base-url http://localhost:8081 --token <dojo-api-key> \
  --org org-demo --limit 10 --dry-run   # inspect, then drop --dry-run
```

Smoke check:
`curl -s "http://localhost:8081/api/v2/findings/?limit=1&related_fields=true" -H "Authorization: Token <key>"`.

### Greenbone/OpenVAS evidence through DefectDojo

The staging path does not run a Greenbone server and the Hub has no native
Greenbone/OpenVAS client or parser. DefectDojo is the scanner evidence
producer and parser; the Hub reads the resulting finding like any other
DefectDojo finding.

To import a report into the DefectDojo sandbox:

1. In the DefectDojo UI, open the target product and engagement, then choose
   **Import Scan**. Upload the Greenbone/OpenVAS report and choose **OpenVAS
   Scan** (or the installed **Greenbone...** scan type). For an existing test,
   use **Reimport Scan** with the same scan type so DefectDojo applies its
   normal finding deduplication.
2. Verify the actual findings-list response with `related_fields=true`:
   `test` and `found_by` may be integer IDs rather than labels. Read the
   scanner provenance from `related_fields.test.test_type.name` and the test
   identifier from `related_fields.test.id`. If the list response does not
   include the related test object, fetch `/api/v2/tests/{test_id}/` and
   inspect its `test_type.name`. A verified finding can carry a Jira key from
   DefectDojo's native Jira integration.
3. Prepare the authenticated Hub-side join before enqueueing the finding. The
   asset alias must match the finding's `host` or `service` value (the fixture
   uses `payments-api-3`), and the finding must have `verified=true`, a CVE,
   and a `purl`/`component_purl` plus component version. The purl is the
   deterministic join to the SBOM component; without it the bridge retains
   evidence but deliberately does not auto-create a case.

   ```bash
   export HUB_API=http://127.0.0.1:8000
   curl -fsS -X POST "$HUB_API/api/v1/organizations/org-demo/assets/import" \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: text/csv" \
     --data-binary $'hostname,name,criticality,internet_exposure\npayments-api-3,Payments API,critical,external\n'

   curl -fsS -X POST "$HUB_API/api/v1/organizations/org-demo/sboms" \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Idempotency-Key: openvas-evidence-sbom" \
     -H "Content-Type: application/json" \
     --data '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"openssl","version":"3.0.2","purl":"pkg:deb/debian/openssl@3.0.2"}]}'
   ```

   Inspect the real finding before proceeding:

   ```bash
   curl -fsS "http://localhost:8081/api/v2/findings/?limit=10&ordering=-id&related_fields=true" \
     -H "Authorization: Token <dojo-api-key>" |
     jq '.results[] | {id, verified, cve, host, service, component_purl, component_version, related_fields}'
   ```

4. Fetch the finding through the existing DefectDojo path. For a direct
   sandbox run, inspect first and then enqueue it with:

   ```bash
   uv run python scripts/sandbox_fetch.py defectdojo \
     --base-url http://localhost:8081 --token <dojo-api-key> \
     --org org-demo --limit 10 --dry-run
   # Repeat without --dry-run after reviewing the payload.
   ```

   For the product polling path, set `DEFECTDOJO_BASE_URL`,
   `DEFECTDOJO_API_TOKEN`, and `POLL_ORGANIZATION_ID` as shown in the
   host-run setup, then run `uv run python -m vulnops.workers.polling`.
5. Watch the host worker/orchestrator/poller terminals. The existing
   DefectDojo bridge persists scanner provenance in `scan_metadata`, the
   ingestion outbox, and the audit reason. Verified findings continue through
   the generic `scanner_confirmed` path; the orchestrator creates the exposure
   and case and records any DefectDojo Jira issue key (including
   `related_fields.jira.key`) as the external ticket. Confirm the authenticated
   result:

   ```bash
   curl -fsS "$HUB_API/api/v1/organizations/org-demo/exposures?state=active" \
     -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
   curl -fsS "$HUB_API/api/v1/organizations/org-demo/cases" \
     -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
   ```

No Greenbone-specific poller, API client, XML parser, or Hub-native bridge is
required for this procedure. Re-running the fetch is expected to be
idempotent for an unchanged finding. Both the product poller and
`scripts/sandbox_fetch.py` request `related_fields=true` so the bridge can
retain scanner provenance from the real findings-list shape. CI uses
checked-in DefectDojo-shaped fixtures; it does not contact a live Greenbone
server.

### Wazuh manager

```bash
docker compose -f deploy/docker-compose.staging.yml --env-file deploy/.env.staging \
  --profile wazuh up -d
```

The manager API is on `https://localhost:55000` (self-signed TLS; the fetch
script accepts it because the sandbox CA is not trusted). The stock manager
image defaults to API user `wazuh` / password `wazuh`; override
`WAZUH_API_USER` / `WAZUH_API_PASSWORD` in `deploy/.env.staging` if you
change them. Enroll at least one agent — e.g. run the Wazuh agent container —
so the package inventory is non-empty:

```bash
uv run python scripts/sandbox_fetch.py wazuh \
  --base-url https://localhost:55000 --user wazuh \
  --password '<WAZUH_API_PASSWORD>' --org org-demo --dry-run
```

Smoke check: `curl -sk -u <user>:<pass> https://localhost:55000/agents`.

Note: the indexer is intentionally not part of this profile. The manager API
already serves agent inventory and syscollector package lists, which is the
evidence the acceptance matrix requires; adding the indexer (vulnerability
detection indexing, dashboard) needs certificate generation and
`vm.max_map_count=262144` inside the Docker VM and is a follow-up.

### Keycloak

```bash
docker compose -f deploy/docker-compose.staging.yml --env-file deploy/.env.staging \
  --profile keycloak up -d
```

Realm `vulnops` is imported from `deploy/keycloak/vulnops-realm.json` on
first start (empty volume). Realm claims match the application settings:
`organizations` (org ids), `roles` (viewer/owner/auditor/risk_approver/admin),
`principal_type`, and audience `vulnops-api`. Note: the import's
`defaultDefaultClientScopes` replaces the built-in client scopes, so tokens
carry `vulnops-claims` plus `openid` only — sufficient for API verification
claims, but add built-in scopes back in the Keycloak admin console if a test
needs `profile`/`email` claims. Seeded users (password grant is enabled on
both clients for scripted evidence runs):

| User | Organizations | Roles |
| --- | --- | --- |
| `owner-demo` | org-demo | owner |
| `approver-demo` | org-demo | owner, risk_approver |
| `auditor-demo` | org-demo | auditor |
| `viewer-demo` | org-demo | viewer |
| `admin-demo` | org-demo | admin |
| `owner-other` | org-other | owner |

For the full evidence path, use the seeded `admin-demo` identity because
`asset:write` and `sbom:write` are required to prepare matching inventory.
Get a token and keep it in the shell only:

```bash
export ACCESS_TOKEN="$(
  curl -fsS http://localhost:8082/realms/vulnops/protocol/openid-connect/token \
  -d grant_type=password -d client_id=vulnops-console \
  -d username=admin-demo -d 'password=sandbox-admin-user-password' \
  -d scope=openid |
  python -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
)"
test -n "$ACCESS_TOKEN"
```

For a host-run API, use this shell configuration and start only the backing
services from the root compose file:

```bash
docker compose up -d postgres valkey minio

export ENVIRONMENT=staging
export AUTH_TEST_BYPASS_ENABLED=false
export OIDC_ALLOW_INSECURE_LOOPBACK=true
export OIDC_ISSUER_URL=http://127.0.0.1:8082/realms/vulnops
export OIDC_AUDIENCE=vulnops-api
export DATABASE_URL=postgresql+psycopg2://vulnops:vulnops@127.0.0.1:5432/vulnops
export REDIS_URL=redis://127.0.0.1:6379/0
export OBJECT_STORAGE_ENDPOINT=http://127.0.0.1:9000
export OBJECT_STORAGE_BUCKET=vulnops-snapshots
export OBJECT_STORAGE_ACCESS_KEY=minioadmin
export OBJECT_STORAGE_SECRET_KEY=minioadmin
export DEFECTDOJO_BASE_URL=http://127.0.0.1:8081
export DEFECTDOJO_API_TOKEN='<dojo-api-key>'
export POLL_ORGANIZATION_ID=org-demo
export DEFECTDOJO_POLL_INTERVAL_SECONDS=15

uv run alembic upgrade head
```

In four host terminals, run the API and the existing product paths:

```bash
uv run uvicorn vulnops.main:app --host 127.0.0.1 --port 8000
uv run python -m vulnops.workers.ingestion
uv run python -m vulnops.workers.orchestration
uv run python -m vulnops.workers.polling
```

Confirm that the token is accepted without the test bypass:

```bash
curl -fsS http://127.0.0.1:8000/api/v1/organizations/org-demo/cases \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

The worker and poller do not need an issuer for source-ingestion evidence, but
they use the same host database and Valkey settings above. Do not start the
root `api` service for this path; its container cannot use the loopback
Keycloak issuer. A Dockerized API instead needs a TLS-published issuer and a
trusted CA. Removing `AUTH_TEST_BYPASS_ENABLED` is mandatory for API evidence.

### Vulnerability-Lookup

```bash
git clone https://github.com/vulnerability-lookup/vulnerability-lookup.git D:/dev-cache/vulnerability-lookup
cd D:/dev-cache/vulnerability-lookup
cp .env.sample .env   # review the defaults; keep enabled sources minimal
docker compose up -d
```

It publishes port 10001. To let the VulnOps api/worker reach it over the
compose default network, connect the running stack to the clone's network
(or use `host.docker.internal:10001`):

```bash
docker network connect vulnerability-lookup_default vulnops-api-1
docker network connect vulnerability-lookup_default vulnops-worker-1
```

Then set `VULNERABILITY_LOOKUP_BASE_URL=http://vulnlookup:10001` on the
api/worker services (or `http://host.docker.internal:10001` without the
network connect) and restart. Smoke check:
`curl -s http://localhost:10001/api/cve/CVE-2024-3094`.

## End-to-end verification loop

1. Start Keycloak, DefectDojo, and the host-run API/worker/orchestrator/poller
   using the authenticated workflow topology above.
2. Obtain the Keycloak token with `AUTH_TEST_BYPASS_ENABLED=false`.
3. Submit the matching asset and SBOM with that bearer token.
4. Import/reimport the OpenVAS report in DefectDojo and inspect the verified
   finding's host, purl/version, and optional Jira key.
5. Let the product poller enqueue the finding and watch the host worker and
   orchestrator terminals.
6. Confirm the active `scanner_confirmed` exposure and case through the
   authenticated API, then replay the same poll and confirm no duplicate
   snapshot, exposure, or case.
7. Record the run in the evidence log below with date, commit, and outcome.

## Evidence log

| Date | Commit | Scenario | Sandbox | Outcome | Notes |
| --- | --- | --- | --- | --- | --- |
| 2026-09-08 | e69ecc1 (staging files uncommitted) | OIDC authentication boundary: token verify, issuer/audience/kid checks against a configured IdP | Keycloak 26.3 (`vulnops` realm) | PASS | Password-grant tokens verified by `OIDCVerifier`; fixes applied to realm: explicit `basic` scope (`oidc-sub-mapper`) because the import replaces built-in scopes, audience mapper needs `access.token.claim`, `principal_type` must be `human`/`service` |
| 2026-09-08 | e69ecc1 (staging files uncommitted) | Organization RBAC: owner allowed, cross-org hidden (404), auditor read, unauthenticated 401 | Keycloak 26.3 + host-run API | PASS | API run on host because the verifier only allows http for loopback issuer URLs; `owner-demo`→200, `owner-other`→404, `auditor-demo`→200, no token→401 |
| 2026-09-08 | e69ecc1 (staging files uncommitted) | Repeated scanner import: real DefectDojo reimport keeps one snapshot, no duplicate cases | DefectDojo (docker) + fetch script + worker | PASS (pipeline) | Real finding re-fetched twice → exactly 1 `source_snapshots` row, 0 cases (no asset/SBOM match — matching decides); external-ticket/outbox dedup not exercised |
| 2026-09-08 | e69ecc1 (staging files uncommitted) | Wazuh agent package inventory via manager API | Wazuh manager 4.12 | PASS (API) | JWT auth verified, 119 package events shaped for `WazuhBridge` (dry-run); queue ingestion not yet run end to end |
| 2026-09-08 | 19b55bf | Wazuh package events ingested end to end through the queue | Wazuh manager + fetch script + worker | PASS | 119/119 jobs processed, 119 distinct `source_snapshots` rows (`agent:cve:package:version` keys), no duplicates |
| 2026-09-08 | 19b55bf | SBOM ingestion with authenticated principal (admin role for `sbom:write`) | Keycloak + host API | PASS | CycloneDX accepted; same content + Idempotency-Key returns the same `sbom_id` (content-addressed); different content under the same key creates a new document; occurrences + `vulnops.sbom.processed.v1` outbox emitted |
| 2026-09-08 | 19b55bf | GAP: no exposure-generation orchestration | — | OPEN | `exposures` table has no writer; the DefectDojo bridge deliberately never creates cases and only emits outbox evidence; `POST /cases` links existing exposure ids. Fixture-level matching is proven, but outbox→intel→match→exposure/case orchestration is an unimplemented product slice |
| 2026-09-08 | 19b55bf | Authenticated case creation with P1 SLA clock | Keycloak + host API | PASS | `owner-demo` created CASE-85CA9C76; due date = +3 days per P1 policy |
| 2026-09-08 | e69ecc1 (staging files uncommitted) | Container builds behind TLS interception | Docker Desktop | PASS | Product Dockerfile fails under Kaspersky MITM; local `deploy/Dockerfile.local` + compose override inject the corporate CA (git-ignored) |
| 2026-09-09 | 2fade00 | SBOM ingestion → orchestration with version-qualified purl `pkg:pypi/urllib3@1.26.17` | Host API + orchestration worker + real api.osv.dev | FAIL (dead-lettered) | `sbom_96b6cde398fb` accepted (HTTP 201); outbox event `evt_02734d9f98c0` retried to 8/8 attempts, never delivered, 0 exposures. Real OSV `POST /v1/querybatch` returns 400 `"version specified in params and PURL query"`: `OSVAdapter.lookup_batch` sends the version-qualified purl AND a separate `version` param. Two stale 2026-09-08 sbom events (`evt_cd0f73be8011`, `evt_a6a11796f133`) failed identically at worker startup and are also dead-lettered at the attempt cap |
| 2026-09-09 | 2fade00 | SBOM ingestion → orchestration closed loop with `pkg:pypi/urllib3` + version `1.26.17` (version qualifier dropped — the one permitted alternative) | Host API + orchestration worker + real api.osv.dev | PARTIAL (loop closed to candidate) | `sbom_e8bbb9b38484` accepted; event delivered ("orchestrator delivered 1 event(s)", real OSV querybatch HTTP 200). 14 exposures written, all `match_class=candidate`, `state=candidate`, priority P4, `policy_version=risk-2026-09-01`, rule `candidate.fallback`, confidence 0.4, matcher 2026.1, `detection_context=sbom:sbom_e8bbb9b38484` — e.g. `exp_0a0d4ca5acb8` GHSA-2xpw-w6gg-jr37, `exp_21062c7b315f` GHSA-34jh-p97f-mpxf (14 ids: 7 GHSA + 7 PYSEC incl. PYSEC-2023-212, PYSEC-2026-141). No matched advisory produced a deterministic match, so no auto-created case (`case_auto_create_enabled=true` gates on deterministic/confirmed) and no new SLA clock; `case_exposures` stays 0 and the only case remains the pre-existing CASE-85CA9C76 (P1, due 2026-09-11, from the 2026-09-08 run). Root cause verified against the live API: real `/v1/querybatch` returns only `{id, modified}` per vuln — no `affected` ranges — while single `POST /v1/query` returns full records (GHSA-2xpw-w6gg-jr37: PyPI ECOSYSTEM range introduced 1.0 → fixed 2.6.0, `1.26.17` listed in `versions`, i.e. in range). Deterministic matching + case auto-creation therefore remain fixture-proven only |

| 2026-09-09 | af5bcd7 | Backup/restore drill (PostgreSQL) | vulnops-hub-postgres-1 | PASS | `pg_dump -Fc` (360 KB) → restore into isolated `vulnops_restore_test` DB → row counts identical to source (snapshots 194, exposures 14, outbox 1701 / 122 delivered, cases 757) |
| 2026-09-09 | af5bcd7 | Object-store digest consistency | local `./storage` backing store | PASS (with finding) | SBOM raw objects live under `./storage/sbom/<org>/<digest>.json` (MVP local backing); filename == content SHA-256 verified. Finding: host-run staging has no `OBJECT_STORAGE_*` config, so `s3://` URIs are logical only and MinIO stays empty in this topology; MinIO/S3 becomes exercisable only with containerized api/worker |
| 2026-09-09 | af5bcd7 | Outbox cursor recovery + replay idempotency | orchestrator (host) | PASS | Reset a delivered SBOM event (`delivered_at=NULL, attempts=0`) → orchestrator re-processed it against live OSV: same 14 exposures retained, zero duplicate exposure keys table-wide, zero duplicate case-exposure links. The drain loop also consumed the 70+ event backlog: 24 deterministic matches auto-created cases with SLA clocks — deterministic→auto-case verified at scale on the live API |
| 2026-09-09 | af5bcd7 | Ops finding: test-suite pollution of staging DB | local Postgres | OPEN | The developer `.env` points `DATABASE_URL` at the staging Postgres, so every API test run writes fixtures there (757 test-residue cases). Use a dedicated test database for suite runs; the 4 DB-dependent auth failures fail only against the polluted instance and pass on a fresh one |
| 2026-09-09 | af5bcd7 | Source outage: OSV unreachable during SBOM evaluation | dead-proxy simulation | PASS | Per-component failure logged with identity (WARNING), event NOT delivered (0 delivered), deferred with ERROR to next poll; exposures table unchanged (119) — no silent downgrade. Poison path: attempts pushed to cap → ERROR "dead-lettered after 8 attempts", event excluded from future claims; exposures still unchanged |
| 2026-09-09 | 3265d9b | Vulnerability-Lookup sandbox bring-up | local clone + official compose | PASS (import ongoing) | Stack deployed and healthy (app + kvrocks + valkey + postgres), first-start source import (CSAF feeds) in progress; API smoke deferred until the web server binds :10001. Gotchas recorded: clone with CRLF breaks its startup script (`sleep infinity\r`) — fix with `sed -i 's/\r$//'` on *.sh and rebuild; `poetry install` in build is flaky on the intercepted network (retry); compose needs the Docker bin dir on PATH for the credential helper |
| 2026-09-12 | c0017ca | Public OpenVAS report parsed by DefectDojo, then product poller → Valkey → worker → outbox/orchestrator | Docker Desktop + DefectDojo 2.51 sandbox | PASS (ingress/replay) | A public legacy OpenVAS XML fixture was sanitized to 31 parser-valid results and imported/reimported as **OpenVAS Parser v2**; DefectDojo held 24 findings. The live poller fetched the real `related_fields=true` API shape, persisted the `defectdojo` source-health cursor at 24, and delivered 24 evidence outbox events. The sandbox ignored `id__gt`; the poller now pages with `offset` and filters by cursor locally. After the saved cursor was restored following the pre-fix test, two 15-second cycles left 48 existing snapshots/events and queue depth 0 (no new work). Migration gating was also exercised: `migrate` completed before dependent services started. API/case and Jira-link evidence remain open here because this run intentionally had no configured OIDC issuer/audience and no Jira integration. |
| 2026-09-12 | c0017ca | Containerized API against local Keycloak | Docker Desktop + Keycloak 26.3 | BLOCKED BY SAFE CONFIGURATION | Keycloak realm initialized, but its plain-HTTP issuer is `127.0.0.1` on the host. Pointing the API container to `host.docker.internal` is rejected by the verifier's loopback-only HTTP rule; test bypass was not enabled. Use TLS for a containerized API acceptance run, or run the API on the host for this local sandbox. |

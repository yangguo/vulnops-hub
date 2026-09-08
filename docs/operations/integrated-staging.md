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
- The VulnOps api/worker containers (from the root `docker-compose.yml`)
  reach sandboxes through `http://host.docker.internal:<port>`, so the
  application compose file stays untouched.
- DefectDojo/Wazuh records enter the pipeline via the queue: fetch script →
  Valkey `vulnops:ingest` → ingestion worker → bridges. The product-level
  HTTP polling adapters are a future slice; `scripts/sandbox_fetch.py` stands
  in for them.
- Vulnerability-Lookup is launched from its own repository (it builds from
  source with its own kvrocks/valkey/postgres backing services).

## Prerequisites

- Docker Desktop with the WSL2 backend, disk image location on `D:\Docker`
  (see the project memory notes; C-drive space is scarce).
- The VulnOps stack running: `docker compose up -d` from the repo root, then
  `docker compose exec api alembic upgrade head` if migrations were not
  applied during image start.
- Copy credentials: `cp deploy/.env.staging.example deploy/.env.staging`.
- **TLS-intercepting networks (corporate MITM):** the product `Dockerfile`
  fails with `SELF_SIGNED_CERT_IN_CHAIN` inside build containers. The local
  workaround (git-ignored, not committed) is `deploy/Dockerfile.local` plus a
  `docker-compose.override.yml` that selects it, both injecting the corporate
  root CA via `NODE_EXTRA_CA_CERTS` / `PIP_CERT` / `update-ca-certificates`.
  See the evidence log entry dated 2026-09-08.

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

Smoke check: `curl -s http://localhost:8081/api/v2/findings/?limit=1 -H "Authorization: Token <key>"`.

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
| `owner-other` | org-other | owner |

Get a token and demonstrate organization claims:

```bash
curl -s http://localhost:8082/realms/vulnops/protocol/openid-connect/token \
  -d grant_type=password -d client_id=vulnops-console \
  -d username=owner-demo -d 'password=sandbox-owner-password' \
  -d scope=openid | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
```

Point the VulnOps stack at it: set `OIDC_ISSUER_URL=http://host.docker.internal:8082/realms/vulnops`
and `OIDC_AUDIENCE=vulnops-api` on the api/worker services, then restart the
stack. **Removing `AUTH_TEST_BYPASS_ENABLED` is mandatory for this evidence.**

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

1. Start the VulnOps stack and the sandbox profiles needed for the scenario.
2. Submit an SBOM or asset so matching has a target.
3. Run `scripts/sandbox_fetch.py` for the source under test.
4. Watch the worker: `docker compose logs -f worker`.
5. Confirm the exposure/case appears (`/api/v1/organizations/org-demo/cases`)
   and that replaying the same fetch does not duplicate cases (the bridge
   deduplicates by source record id and digest).
6. Record the run in the evidence log below with date, commit, and outcome.

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


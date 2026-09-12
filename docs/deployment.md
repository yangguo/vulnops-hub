# Deployment Design

> **Document status:** Target deployment architecture with an as-built preview
> subsection. Local SQLite evaluation, the checked Docker Compose/Helm assets,
> CI container smoke tests, and automated OIDC/RBAC enforcement verification are
> currently covered. Real production IdP integration, production
> certification, backup/restore drills, and the full worker topology remain
> open.

## 1. Supported deployment posture

The MVP targets a self-hosted, single-organization deployment. The architecture
keeps organization scoping in the data model so a future multi-tenant version
does not require rekeying core records, but tenant isolation, billing, and
cross-tenant administration are not MVP claims.

Three modes are defined:

| Mode | Intended use | Components |
| --- | --- | --- |
| Local evaluation | Developer/demo, disposable data | Authenticated API on SQLite; optional Vite dev server |
| Integrated staging | Adapter contract tests | Local core plus connected sandbox DefectDojo/Vulnerability-Lookup/Wazuh |
| Production target | Internal enterprise service | Kubernetes/containers, managed PostgreSQL/object store, queue, OIDC, observability |

### As-built preview

- Bare local mode runs FastAPI against `vulnops.db`; it requires a configured
  OIDC issuer for API and console evaluation.
- Docker Compose starts the API, ingestion worker, PostgreSQL, Valkey, and
  MinIO with development credentials; the API remains bearer-token protected.
- The multi-stage image builds and serves the Vue SPA and is smoke-tested in
  CI through `/health/live`, `/health/ready`, and `/`.
- Helm manifests are templates, not evidence of a production deployment.
- OIDC bearer validation, organization scope, and route capabilities are
  enforced server-side. Missing issuer configuration fails startup closed.
- The loopback-only `tests/e2e/oidc_test_issuer.py` provides CI/local browser
  verification identities; it is test infrastructure and is not a deployment
  identity provider.

DefectDojo, Vulnerability-Lookup, Wazuh, Greenbone, and ITSM platforms are
external services. A deployment may enable only the adapters it operates.

## 2. Core runtime topology

~~~mermaid
flowchart TB
  U["Analysts / remediation owners"] --> GW["Ingress / API gateway"]
  IDP["OIDC identity provider"] --> GW
  GW --> API["VulnOps Hub API"]
  API --> PG[("PostgreSQL")]
  API --> OBJ[("Object storage")]
  API --> Q["Valkey or durable queue"]
  W1["Ingestion workers"] --> Q
  W2["Matching and SLA workers"] --> Q
  W3["Outbox delivery workers"] --> Q
  W1 --> PG
  W2 --> PG
  W3 --> PG
  W1 --> EXT["Feeds and external platforms"]
  W3 --> EXT
  OTEL["OpenTelemetry collector"] <-->|traces, logs, metrics| API
  OTEL <-->|traces, logs, metrics| W1
  OTEL <-->|traces, logs, metrics| W2
  OTEL <-->|traces, logs, metrics| W3
~~~

The first production build may use a database-backed job table plus Valkey for
work coordination. A message broker is introduced only when queue throughput,
retention, or multiple independent consumers make it necessary. Jobs must
remain replayable from source snapshots in either model.

## 3. Configuration and secrets

Configuration is immutable per deployment and versioned in Git or a deployment
system. Secret values never enter that configuration file, Git, events, logs,
or raw source snapshots.

| Configuration group | Examples |
| --- | --- |
| Core | public URL, timezone, database/object-store endpoints, queue limits |
| Identity | issuer URL, audience, claim names, group-to-role mapping, service-token issuers |
| Source adapters | base URL, schedule, cursor policy, rate limit, enabled source families |
| External platforms | DefectDojo, Vulnerability-Lookup, Wazuh, Greenbone, Jira endpoints and mappings |
| Risk/SLA | active policy version, escalation routes, calendar, exception approval policy |
| Retention | raw report/SBOM retention, audit retention, deletion/legal-hold policy |
| Operations | telemetry endpoint, alert destinations, backup/recovery objectives |

Credentials live in a secret manager, Kubernetes Secrets synchronized from it,
or an equivalent secret-injection mechanism. Rotate adapter tokens without
redeploying code and make all access scopes minimal.

### Authentication configuration

Set these values in the API environment for local, staging, and production
deployments:

| Variable | Requirement | Purpose |
| --- | --- | --- |
| `OIDC_ISSUER_URL` | required | HTTPS issuer URL used for discovery and JWKS retrieval; local staging may explicitly opt into an IP-loopback HTTP issuer with `OIDC_ALLOW_INSECURE_LOOPBACK=true` |
| `OIDC_AUDIENCE` | required | Audience accepted on API access tokens |
| `OIDC_ALLOWED_ALGORITHMS` | default `RS256` | Allowed asymmetric signing algorithms |
| `OIDC_ALLOW_INSECURE_LOOPBACK` | default `false` | Staging-only host-run opt-in for an IP-loopback HTTP issuer; rejected outside `ENVIRONMENT=staging` |
| `OIDC_ORGANIZATION_CLAIM` | default `organizations` | Claim containing organization IDs |
| `OIDC_ROLE_CLAIM` | default `roles` | Human role claim |
| `OIDC_SERVICE_SCOPE_CLAIM` | default `scope` | Named service-token scope claim |
| `OIDC_PRINCIPAL_TYPE_CLAIM` | default `principal_type` | Required `human` or `service` claim |

The API fails startup when the issuer or audience is absent. The explicit
`AUTH_TEST_BYPASS_ENABLED=true` mode is accepted only with
`ENVIRONMENT=test`; it is reserved for backend test fixtures and must not be
enabled in a deployed environment. The server is the
authorization authority even when the console hides controls based on token
claims.

Production-shaped deployments must use an **HTTPS** `OIDC_ISSUER_URL`, keep
`OIDC_ALLOW_INSECURE_LOOPBACK=false`, and never enable the test bypass. See
[production IdP integration](operations/production-idp-integration.md) for
scaffold env/Helm templates and the adopter checklist. That guide is not
evidence of live production certification.

The frontend receives its non-secret OIDC client settings at build time through
`frontend/.env` (see `frontend/.env.example`). The redirect URI must be
registered with the configured provider. Docker Compose passes the API OIDC
settings from the root `.env`; a blank value intentionally causes the API to
fail closed rather than starting an unauthenticated service.

For reproducible browser verification, the Playwright configuration starts the
loopback test issuer, configures the API with `AUTH_TEST_BYPASS_ENABLED=false`,
and builds the SPA with `VITE_OIDC_AUTHORITY=http://127.0.0.1:9000`, client ID
`vulnops-e2e`, and the Playwright callback URL. The resulting tests prove login,
auditor read-only behavior, owner transition authorization, expired-token
rejection, and cross-organization 404 denial. This fixture evidence does not
claim integration with a production IdP.

## 4. Storage and recovery

### PostgreSQL

PostgreSQL stores transactional state, source-snapshot metadata, audit events,
outbox records, adapter cursors, and policy versions. Enable point-in-time
recovery for production. Test a restore to an isolated environment at a defined
cadence, including object-store consistency checks.

### Object storage

Raw scanner reports, SBOMs, large advisory payloads, and export artifacts reside
in private object storage. Each object has a content SHA-256, source snapshot
ID, classification, encryption metadata, and retention policy. The database
records the content address; it must not assume a mutable file path is evidence.

### Backups

Recovery documentation must cover:

1. restore database to a selected point;
2. restore/version the corresponding object-store bucket;
3. rehydrate adapter cursor state;
4. verify source snapshot digest consistency;
5. re-run projections safely through idempotent replay;
6. confirm no external ticket action is re-emitted without outbox deduplication.

## 5. Network and feed synchronization

Production egress should traverse an allowlisted proxy. Per-source schedules
are configurable and driven by publication/freshness characteristics, not a
single blanket cron interval. The system records both last checked and last
successfully ingested times.

For each source:

- validate TLS and provider identity;
- obey documented API terms, rate limits, cache headers, and pagination;
- persist a cursor only after successful, durable processing;
- retain the raw response digest and source timestamp;
- alert on staleness rather than treating stale content as absence of risk.

Air-gapped deployments may import signed, pre-fetched source bundles or connect
to local Vulnerability-Lookup/Wazuh feeds. Offline mode requires an explicit
freshness policy; it must remain visible to case owners.

## 6. Security hardening baseline

- TLS for all ingress and service-to-service connections.
- OIDC plus short-lived service credentials; no shared administrator account.
- Role/attribute authorization and separate permission for raw evidence.
- Database/object-store encryption, backups encrypted with separate keys.
- Secrets redaction in structured logs and error payloads.
- Content-type, schema, size, and archive-bomb validation for report uploads.
- Egress allowlists, DNS control, and SSRF-resistant adapter clients.
- Dependency update, SAST, secret scanning, SBOM generation, and signed
  container-image pipeline for the Hub itself.
- Administrative actions, policy changes, exception approvals, and export
  downloads recorded as audit events.

## 7. Observability and operational metrics

### Health signals

- API readiness/liveness and migration version.
- Queue depth, job latency, retry rate, dead-letter count.
- Adapter last success, cursor lag, source freshness, and parse rejection rate.
- Matching throughput, candidate rate, ambiguity rate, and replay duration.
- Open cases by priority, SLA breach rate, exception expiry count, verification
  insufficiency rate, and coverage-gap count.
- Outbox delivery success/failure and external-sync conflict rate.
- Database connection saturation, storage growth, backup success, and restore-test age.

### Minimum alerts

- source becomes stale beyond its policy threshold;
- source snapshots repeatedly fail validation;
- high-priority case SLA breach or exception about to expire;
- queue remains above threshold or dead letters increase;
- backup fails or restore-test evidence is overdue;
- external ticket projection fails repeatedly;
- unmatched/ambiguous asset rate spikes after an adapter change.

## 8. Upgrade and migration policy

Schema migrations are forward-compatible when possible, gated by application
version, and tested on a production-like snapshot. Adapter upgrades must support
parallel parser versions or a bounded, versioned replay plan. No migration may
silently convert a candidate match into a confirmed match; re-evaluation must
record its matcher and policy version.

## 9. Capacity starting point

Size from measured workload: assets, component occurrences, scan/report volume,
source update rate, retention, desired freshness, and case/event history. Do
not choose production node sizes solely from CVE count. Benchmark with anonymized
realistic fixtures before setting SLOs, especially for large SBOM batches and
replays.

# API Design

> **Document status:** Sections labelled **Current implementation** describe
> the M1 technical preview. Other resource and event contracts are target-state
> design and must not be assumed to exist. The authoritative implemented
> contract is `openapi/openapi.yaml`.

## Current implementation

The preview exposes health probes and these organization-scoped resources:

| Method and path | Status |
| --- | --- |
| `GET /health/live`, `GET /health/ready` | Implemented |
| `POST /api/v1/organizations/{org_id}/sboms` | Implemented |
| `GET /api/v1/organizations/{org_id}/sboms/{sbom_id}` | Implemented |
| `GET`, `POST /api/v1/organizations/{org_id}/cases` | Implemented |
| `GET /api/v1/organizations/{org_id}/cases/{case_id}` | Implemented |
| `GET /api/v1/organizations/{org_id}/cases/{case_id}/allowed-transitions` | Implemented |
| `POST /api/v1/organizations/{org_id}/cases/{case_id}/transitions` | Implemented |
| `GET`, `POST /api/v1/organizations/{org_id}/cases/{case_id}/risk-decisions` | Implemented |
| `GET`, `POST /api/v1/organizations/{org_id}/cases/{case_id}/verifications` | Implemented |

Authentication is not enforced yet. Pagination currently uses `page` and
`page_size`, not the target opaque-cursor contract. Assets, services,
observations, components, intelligence/source health, evidence, exposures,
policies, submissions/jobs, and outbound webhooks below remain planned unless
added to the checked OpenAPI document.

## 1. Target API principles

The public API is REST/JSON with an OpenAPI 3.1 contract. It is designed for
automation first; a web UI is a client of the same API.

- Base path: **/api/v1**.
- Auth: OIDC bearer tokens for people and scoped service tokens for adapters.
- Organization scope: explicit path parameter or trusted token claim; never an
  implicit default for service accounts.
- Idempotency: all write endpoints accept an **Idempotency-Key** header.
- Tracing: response and event headers include **X-Request-ID** and correlation
  identifiers.
- Pagination: opaque cursor with a stable sort order.
- Concurrency: mutable resources return entity tags; clients use **If-Match** for
  conflict-sensitive updates.
- Asynchronous ingestion: large uploads and feed jobs return a submission
  resource with state instead of holding a request open.
- Errors: Problem Details compatible JSON with an actionable error code,
  field-level validation detail, and correlation ID.

The API must not expose raw report payloads without authorization; callers
receive source metadata and signed/authorized retrieval links where policy
allows.

## 2. Target core resources

| Resource | Purpose | Representative endpoints |
| --- | --- | --- |
| Assets | Canonical technical targets and aliases | GET/POST /assets; GET/PATCH /assets/{id} |
| Services | Business/application context and ownership | GET/POST /services |
| Observations | Time-bounded CMDB, Wazuh, cloud, or scanner facts | POST /asset-observations |
| SBOMs | Immutable documents and parsed component occurrences | POST /sboms; GET /sboms/{id} |
| Components | Normalized purl/package identities | GET /components; GET /components/{id} |
| Intelligence | Advisory views, source health, and source snapshots | GET /vulnerabilities/{id}; GET /sources |
| Evidence | Scanner results, source snapshots, and review evidence | GET /evidence/{id} |
| Exposures | Evaluated asset-component-vulnerability assertions | GET /exposures; GET /exposures/{id} |
| Cases | Workflow, SLA, ownership, and external work links | GET/POST /cases; POST /cases/{id}/transitions |
| Decisions | Risk acceptance, not-affected, or override decisions | POST /cases/{id}/risk-decisions |
| Verification | Positive remediation/retest evidence | POST /cases/{id}/verifications |
| Policy | Versioned risk and SLA policies | GET/POST /policies; POST /policies/{id}/simulate |
| Jobs | Long-running import/evaluation operations | GET /submissions/{id}; GET /jobs/{id} |

## 3. Example command contracts

### 3.1 Submit an SBOM

~~~http
POST /api/v1/organizations/acme/sboms
Content-Type: application/vnd.cyclonedx+json
Idempotency-Key: 52e4f7cb-...

{ ... CycloneDX JSON ... }
~~~

~~~json
{
  "id": "sbom_01J...",
  "status": "accepted",
  "submission_id": "sub_01J...",
  "content_sha256": "ab12...",
  "received_at": "2026-09-05T10:10:00Z"
}
~~~

The asynchronous processor validates schema, captures the immutable source
snapshot, extracts component occurrences, resolves target references, and emits
an sbom.processed event. A validation failure retains metadata and only the
permitted raw payload portion for audit/diagnosis.

### 3.2 Record a scanner observation

~~~http
POST /api/v1/organizations/acme/evidence/scanner-observations
Idempotency-Key: DD:reimport:123456
~~~

~~~json
{
  "source": {
    "type": "defectdojo",
    "instance": "prod-dojo",
    "finding_id": "123456",
    "test_id": "987",
    "url": "https://dojo.example/findings/123456"
  },
  "asset_hints": [
    {"namespace": "cmdb", "value": "CI-009871"},
    {"namespace": "hostname", "value": "payments-api-3"}
  ],
  "vulnerability_aliases": ["CVE-2026-12345"],
  "observed_component": {
    "purl": "pkg:deb/debian/openssl@3.0.2",
    "raw_name": "openssl",
    "raw_version": "3.0.2"
  },
  "scan_run": {
    "id": "scan-2026-09-05-001",
    "completed_at": "2026-09-05T09:59:00Z",
    "scope_status": "complete",
    "credentials_status": "authenticated"
  }
}
~~~

The endpoint accepts evidence, not a request to blindly create a case. The
matching engine decides whether to create/update an Exposure and the policy
engine decides whether a case is required.

### 3.3 List actionable exposures

~~~http
GET /api/v1/organizations/acme/exposures?state=active&priority=P0,P1&include=case,evidence
~~~

~~~json
{
  "data": [
    {
      "id": "exp_01J...",
      "asset": {"id": "ast_01J...", "name": "payments-api-3", "criticality": "critical"},
      "component": {"purl": "pkg:deb/debian/openssl@3.0.2"},
      "vulnerability": {"id": "CVE-2026-12345", "kev": true, "epss": 0.91},
      "match": {"class": "confirmed", "confidence": 0.99, "evidence_ids": ["ev_01J..."]},
      "risk": {"priority": "P0", "policy_version": "risk-2026-09-01"},
      "case": {"id": "case_01J...", "status": "assigned", "due_at": "2026-09-06T10:00:00Z"}
    }
  ],
  "next_cursor": "eyJ..."
}
~~~

### 3.4 Create a governed risk decision

~~~http
POST /api/v1/organizations/acme/cases/case_01J.../risk-decisions
If-Match: "case-version-12"
Idempotency-Key: 71809c5c-...
~~~

~~~json
{
  "type": "risk_accepted",
  "scope": {"exposure_ids": ["exp_01J..."]},
  "reason": "Vendor patch requires a maintenance window.",
  "compensating_controls": ["WAF rule 314", "network segment restricted"],
  "expires_at": "2026-10-05T00:00:00Z",
  "evidence_ids": ["ev_change_459", "ev_waf_22"],
  "requested_by": "user_01J..."
}
~~~

The API returns approval_required until the configured approver role signs the
decision. It never removes the Exposure or stops future evidence reevaluation.

### 3.5 Submit verification

~~~http
POST /api/v1/organizations/acme/cases/case_01J.../verifications
~~~

~~~json
{
  "method": "wazuh_inventory",
  "asserted_result": "remediated",
  "observed_at": "2026-09-05T13:04:00Z",
  "asset_id": "ast_01J...",
  "evidence_ids": ["ev_wazuh_879"],
  "coverage": {
    "status": "complete",
    "scope_version": "inventory-policy-3",
    "freshness_seconds": 900
  }
}
~~~

The server evaluates the verification policy. It may close the case, return it
to work, or record an insufficient-evidence outcome. Callers cannot force
closed by setting a field.

## 4. State transitions

Allowed transitions are exposed by:

~~~http
GET /api/v1/organizations/acme/cases/case_01J.../allowed-transitions
~~~

Transition requests include target state, reason, evidence references, optional
owner, and an idempotency key. The API enforces role, SLA, approval, and
evidence rules on the server. Direct PATCH of a status field is not supported.

## 5. Events and outbound webhooks

Domain events use a CloudEvents-compatible envelope:

~~~json
{
  "specversion": "1.0",
  "id": "evt_01J...",
  "type": "vulnops.case.transitioned.v1",
  "source": "https://hub.example/organizations/acme",
  "subject": "cases/case_01J...",
  "time": "2026-09-05T13:05:00Z",
  "datacontenttype": "application/json",
  "data": {
    "from": "awaiting_verification",
    "to": "closed",
    "reason": "successful Wazuh inventory verification",
    "evidence_ids": ["ev_wazuh_879"],
    "correlation_id": "corr_01J..."
  }
}
~~~

Supported initial event families:

- vulnops.asset.observed.v1
- vulnops.sbom.processed.v1
- vulnops.source.stale.v1
- vulnops.exposure.created.v1
- vulnops.exposure.reopened.v1
- vulnops.case.created.v1
- vulnops.case.transitioned.v1
- vulnops.sla.breached.v1
- vulnops.risk-decision.expired.v1
- vulnops.verification.completed.v1

Webhook delivery is signed, replay-safe, retried with exponential backoff, and
recorded in the outbox ledger. A receiver acknowledges quickly, then performs
its own idempotent processing.

## 6. Error model

~~~json
{
  "type": "https://hub.example/problems/insufficient-verification-coverage",
  "title": "Verification cannot close this case",
  "status": 422,
  "code": "verification_coverage_incomplete",
  "detail": "The associated scanner run did not cover two assets in the case scope.",
  "invalid_params": [],
  "correlation_id": "corr_01J..."
}
~~~

Important error categories:

- asset_identity_ambiguous
- source_snapshot_invalid
- unsupported_version_scheme
- policy_version_not_active
- approval_required
- risk_decision_expired
- verification_coverage_incomplete
- integration_conflict
- idempotency_key_reused_with_different_payload

## 7. Authorization model

Minimum roles:

| Role | Permissions |
| --- | --- |
| Viewer | Read scoped assets, exposures, cases, and permitted evidence |
| Analyst | Triage exposures, submit evidence, request decisions |
| Remediation owner | Update assigned cases and submit verification |
| Risk approver | Approve/revoke decisions within delegated scope |
| Policy administrator | Manage policies, adapters, and SLA configuration |
| Integration service | Only the explicit ingestion/projection scopes granted |
| Auditor | Read audit history and evidence metadata; no mutation |

Authorization is evaluated at organization and business-service/asset-group
scope. Sensitive raw payload access is a separate permission from case access.

## 8. Compatibility and versioning

Versioned endpoints and event types are additive by default. Fields are never
silently reinterpreted. Deprecations publish a replacement, migration guide,
and sunset date. Adapter schema versions and normalized-record versions are
stored with every source snapshot so historical data can be replayed.

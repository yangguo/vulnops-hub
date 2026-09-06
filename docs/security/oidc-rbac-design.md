# OIDC and RBAC Design

> **Status:** Proposed target design for the next M1 implementation slice; not
> implemented in the current technical preview.

## 1. Goal and boundaries

The API must authenticate people and service workloads, derive authorization
from trusted token claims, and enforce organization scope before domain
services execute. The first slice supports one configured OIDC issuer and one
audience per deployment. It does not build an identity provider, user directory,
permission editor, or multi-tenant administration plane.

Until this design is implemented, the service must remain behind an isolated
intranet boundary and must not treat request-body identity or role fields as
trusted authorization evidence.

## 2. Principals and token types

| Principal | Authentication | Intended use |
| --- | --- | --- |
| Human | OIDC access token | Console and interactive API access |
| Service | JWT access token from the configured issuer | CI SBOM submission and adapters |

Required claims are `iss`, `aud`, `exp`, and `sub`. Human display name and
email are optional metadata. Organization and role claims use configurable
claim names so deployments can map their identity provider without changing
domain code.

Tokens are accepted only from the configured issuer, for the configured
audience, with an allowed asymmetric algorithm. The service retrieves keys from
OIDC discovery/JWKS, caches them with a bounded lifetime, and refreshes once on
an unknown `kid`. It fails closed when discovery, signature, issuer, audience,
expiry, or claim validation fails.

## 3. Authorization model

The initial roles are cumulative only where explicitly stated:

| Role | Capabilities |
| --- | --- |
| `viewer` | Read cases and non-sensitive metadata in an allowed organization |
| `owner` | Viewer access plus permitted case transitions and verification submission |
| `auditor` | Read case, decision, verification, provenance, and audit metadata; no mutation |
| `risk_approver` | Viewer access plus approve/reject governed risk decisions |
| `security_lead` | Owner and risk-approver capabilities |
| `admin` | All organization-scoped product operations; raw evidence remains a separate permission |

`evidence:raw:read` is a permission, not an implied role capability. Service
tokens receive named scopes such as `sbom:write` or `evidence:write` and cannot
perform human approvals.

Initial route capabilities are explicit:

| Operation | Required capability |
| --- | --- |
| List/read cases and histories | `case:read` |
| Create or transition a case | `case:write` |
| Request risk acceptance/not-applicable review | `risk:request` |
| Approve or reject an existing risk decision | `risk:approve` |
| Submit verification | `verification:write` |
| Submit/read SBOM metadata | `sbom:write` / `sbom:read` |
| Retrieve future raw evidence | `evidence:raw:read` |

Risk approval is a separate action on an existing decision; the request
endpoint cannot both request and approve a decision. This keeps separation of
duties visible in the HTTP contract and audit trail.

Every request to `/api/v1/organizations/{org_id}` requires `org_id` to appear
in the principal's trusted organization claim. Cross-organization access
returns `404` for resource reads and mutations to avoid disclosing existence.
An authenticated principal lacking a capability within an allowed organization
receives `403`.

## 4. Request flow

1. FastAPI dependency extracts the Bearer token.
2. The OIDC verifier validates cryptography and registered claims.
3. A claim mapper produces an immutable `Principal` containing subject,
   principal type, organization IDs, roles, scopes, and raw-evidence permission.
4. Route dependencies enforce organization membership and required capability.
5. Domain services receive actor identity and trusted approval context; they do
   not parse tokens or trust role fields from JSON.
6. Audit events record subject, principal type, effective roles/scopes,
   organization, request ID, and correlation ID.

The web console uses authorization-code flow with PKCE through
`oidc-client-ts`. Access and refresh tokens use an in-memory store and are never
written to `localStorage` or `sessionStorage`; a page reload starts a new
authorization flow, which may complete silently through the identity provider's
existing session. A future BFF/cookie session requires a separate ADR covering
CSRF, session storage, logout, and key rotation.

## 5. Risk-decision integrity

The current API accepts `requested_by`, `approver`, and `approver_role` fields
in one request. After migration:

- `requested_by` is derived from the authenticated subject.
- Approval identity and role are derived from the principal.
- A caller cannot approve its own request.
- Service tokens cannot approve risk decisions.
- Client-supplied identity fields are ignored or rejected with a documented
  validation error during the breaking-contract transition.
- Approval uses a distinct endpoint requiring `risk:approve`; it records the
  decision ID, outcome, authenticated approver, timestamp, reason, and request
  correlation identifiers.

Existing decision records remain readable. The migration does not rewrite old
actors; it records whether actor provenance was `legacy_request` or
`authenticated_claim`.

## 6. Configuration and failure behavior

Required production settings:

- `OIDC_ISSUER_URL`
- `OIDC_AUDIENCE`
- allowed signing algorithms
- organization claim name
- role claim name
- service-scope claim name

Development bypass is permitted only when `ENVIRONMENT=development` or
`test`, must require an explicit setting, and must create a clearly marked
development principal. Startup must fail if bypass is enabled in staging or
production. Production must also fail startup when OIDC settings are absent.

Return Problem Details-compatible errors:

- `401 authentication_required`: missing token.
- `401 invalid_token`: invalid or expired token.
- `403 insufficient_permission`: authenticated but not authorized.
- `404 resource_not_found`: cross-organization resource access.

Logs may include token subject, issuer, and validation category but never the
token, authorization header, secrets, or raw sensitive claims.

## 7. Verification requirements

- Unit tests cover issuer, audience, expiry, signature, algorithm, `kid`
  refresh, claim mapping, and production bypass rejection.
- API tests cover every current endpoint with missing, valid, insufficient,
  service, and cross-organization principals.
- Risk-decision tests prove request-body role spoofing and self-approval fail.
- Audit tests prove actor provenance comes from the authenticated principal.
- OpenAPI declares the Bearer security scheme and endpoint requirements.
- Browser E2E covers login, expiry/401 handling, read-only auditor UI, and a
  permitted owner transition using a test issuer.

## 8. Deferred decisions

- Multi-issuer federation and per-organization identity providers.
- Fine-grained policy engines such as OPA/Cedar.
- SCIM provisioning and user lifecycle management.
- Browser BFF/session architecture if in-memory PKCE is insufficient.
- Emergency access workflows and privileged production administration.

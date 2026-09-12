# Production identity provider integration

> **Status:** Scaffolding and fail-closed configuration checks ship in M2. This
> document describes the expected production-shaped deployment; it is **not**
> evidence of live certification against a specific enterprise IdP.

## Scope

VulnOps Hub authenticates API and console traffic with **one configured OIDC
issuer** and **one API audience** per deployment. The Hub is an OIDC relying
party only: it does not ship an identity provider, user directory, or
permission editor.

Local integrated staging may continue to use the checked-in Keycloak sandbox
with an explicit host-run loopback opt-in (`ENVIRONMENT=staging` and
`OIDC_ALLOW_INSECURE_LOOPBACK=true`). That path is documented in
[integrated staging](integrated-staging.md) and must not be copied into
production.

## Required API settings

| Variable | Production requirement |
| --- | --- |
| `ENVIRONMENT` | Must be `production` for production-shaped deploys |
| `OIDC_ISSUER_URL` | **HTTPS** issuer URL (scheme `https://`). Used for discovery (`/.well-known/openid-configuration`) and must match token `iss` exactly |
| `OIDC_AUDIENCE` | Non-empty audience accepted on access tokens (`aud`) |
| `OIDC_ALLOWED_ALGORITHMS` | Asymmetric only (default `RS256`); must match IdP signing keys in JWKS |
| `OIDC_ORGANIZATION_CLAIM` | Claim listing organization IDs the principal may access |
| `OIDC_ROLE_CLAIM` | Human role claim mapped to Hub capabilities |
| `OIDC_SERVICE_SCOPE_CLAIM` | Named scopes for service/client tokens |
| `OIDC_PRINCIPAL_TYPE_CLAIM` | Required `human` or `service` discriminator |

### Forbidden in production

| Variable | Why |
| --- | --- |
| `AUTH_TEST_BYPASS_ENABLED=true` | Test-only principal; startup fails unless `ENVIRONMENT=test` |
| `OIDC_ALLOW_INSECURE_LOOPBACK=true` | Staging-only host-run Keycloak opt-in; rejected when `ENVIRONMENT=production` |
| HTTP issuer URLs | Remote HTTP issuers are rejected; loopback HTTP is staging-only |

Startup **fails closed** when production invariants are violated (see
`validate_auth_configuration` and `tests/auth/test_production_idp_config.py`).

## Runtime verification behavior

After startup, the API:

1. Fetches OIDC discovery from `{OIDC_ISSUER_URL}/.well-known/openid-configuration`.
2. Requires discovery `issuer` to equal `OIDC_ISSUER_URL`.
3. Loads JWKS from the discovered `jwks_uri` over **HTTPS** when the issuer is
   HTTPS (HTTP JWKS downgrade is rejected).
4. Validates JWT signature, `iss`, `aud`, `exp`, and required claim types.
5. Refreshes JWKS once on an unknown `kid`, then fails closed.

Organization membership and route capabilities are enforced **after** token
verification; see [OIDC/RBAC design](../security/oidc-rbac-design.md).

## Console (SPA) settings

Build the frontend with production IdP values (placeholders in
`frontend/.env.production.example`):

| Variable | Purpose |
| --- | --- |
| `VITE_OIDC_AUTHORITY` | Same issuer as `OIDC_ISSUER_URL` (HTTPS) |
| `VITE_OIDC_CLIENT_ID` | Public OIDC client id registered at the IdP |
| `VITE_OIDC_REDIRECT_URI` | HTTPS callback URL served by the Hub ingress |
| `VITE_OIDC_POST_LOGOUT_REDIRECT_URI` | HTTPS post-logout landing page |
| `VITE_OIDC_SCOPE` | Typically `openid profile email` plus any IdP-specific scopes |
| Claim mapping vars | Must match API claim names when the IdP uses non-default names |

Use authorization-code flow with PKCE (`oidc-client-ts`). Client secrets for
public SPA clients are not embedded in the repository; register redirect URIs
and CORS at the IdP.

## IdP operator checklist (adopter-owned)

1. Register an OIDC client for the Hub API audience and a public SPA client for
   the console redirect URIs.
2. Publish a **stable HTTPS issuer** reachable from API pods (no mixed HTTP
   discovery/JWKS).
3. Map organization IDs and roles into the configured claims (see staging
   Keycloak realm export for an example shape, not a production template).
4. Issue access tokens whose `aud` includes `OIDC_AUDIENCE`.
5. Confirm JWKS rotation: unknown `kid` should succeed after one refresh.
6. Disable test bypass and loopback flags in all production namespaces.

## Scaffold artifacts (no secrets)

| Artifact | Use |
| --- | --- |
| `deploy/.env.production.example` | Host or compose production-shaped API env |
| `deploy/env/production-idp.example.env` | Snippet overlay for OIDC-only vars |
| `deploy/helm/vulnops-hub/values-production-idp.example.yaml` | Helm value overlay |
| `frontend/.env.production.example` | SPA build-time OIDC placeholders |

Replace `idp.example`, `hub.example`, and audience strings with adopter values.
Store client credentials and database passwords in a secret manager; wire them
through Kubernetes secrets or your platform's external-secrets integration.

## What remains open (not claimed by this slice)

- Dated evidence of login, role mapping, and cross-org denial against a **live
  adopter production IdP** (distinct from local Keycloak and CI test issuers).
- Shared adopter integrated-staging environment and production certification
  sign-off.
- Browser E2E against a real TLS IdP in CI (Playwright continues to use the
  loopback test issuer).

## Related documents

- [Deployment design](../deployment.md) — topology and env tables
- [Integrated staging evidence log](integrated-staging.md) — local Keycloak sandbox
- [OIDC/RBAC design](../security/oidc-rbac-design.md) — capabilities and claim mapping

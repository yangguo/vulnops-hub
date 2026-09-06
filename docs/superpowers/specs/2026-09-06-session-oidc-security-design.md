# Session and OIDC Security Remediation Design

## Goal

Close the Level 3 re-review findings by making every transition to an unauthenticated frontend state purge user-bound browser state, by enforcing secure OIDC discovery and JWKS transport outside explicit local test/dev mode, and by constraining the E2E issuer to loopback use.

## Frontend architecture

`useAuthStore` owns the unauthenticated transition. Its `clearUnauthenticatedSession` action clears the in-memory user and error/auth state, then calls the browser-state cleanup boundary. `clearUserBoundBrowserState` clears both persisted and live organization/SBOM stores. Every path that loses authentication—explicit logout, API 401/token expiry, null or expired startup, callback failure, and `userUnloaded`—uses that action.

SBOM history moves from a component-local ref into `useSbomHistoryStore`. The store owns the persisted history, exposes a monotonically increasing `generation`, resets live history during cleanup, and only records a completed submission when the caller's captured generation is still current. `SbomSubmitView` captures the generation and organization before the request and ignores a successful or failed response from an older generation. Callback identity installation purges state before binding the new identity, so localStorage is never trusted as belonging to an unknown browser user.

`App.vue` catches provider logout failures after local cleanup and routes to `/login`, ensuring a failed provider redirect cannot leave protected UI mounted with stale state.

## OIDC transport architecture

The verifier validates URL syntax and transport at the shared constructor/discovery boundary. HTTPS is required for configured issuers and discovered JWKS URLs by default. An explicit `allow_insecure_loopback` constructor mode permits HTTP only when both URL hosts are IP loopback addresses; `from_settings` enables that mode only for `ENVIRONMENT=development` or `ENVIRONMENT=test`. A configured HTTPS issuer may never use an HTTP JWKS URI, including in loopback mode, preventing transport downgrade.

## Test issuer architecture

The E2E issuer validates that its bind host and advertised issuer host are strict IP loopback addresses before starting. Its authorization and logout redirect sinks accept only the configured Playwright callback and login URLs. Existing loopback CI commands remain unchanged.

## Verification

Frontend Vitest covers each unauthenticated state-loss path, callback/account switching, mounted SBOM history reset, and a late submission response after cleanup. Backend pytest covers remote HTTP issuer rejection, loopback exception, remote HTTP JWKS rejection, and HTTPS-to-HTTP downgrade rejection. Test-issuer unit tests cover host/issuer validation and redirect allowlisting. The final verification runs the complete frontend Vitest suite and the focused backend auth suite.

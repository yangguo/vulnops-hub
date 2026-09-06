# Task 4 report: Organization and capability authorization

## Status

Implemented organization-scoped authorization for all current cases and SBOM
business routes. The requested commit is the final branch commit
`feat(auth): enforce organization RBAC`.

## TDD evidence

### RED

The new authorization suite was first run against the Task 3
authentication-only implementation:

```text
uv run pytest tests/api/test_authorization.py -q
7 failed, 4 passed
```

The expected failures showed that viewer mutation, non-mutating role risk
requests, service case reads, cross-organization reads, and wildcard
organization claims were still accepted or returned ordinary empty responses.

### GREEN

After adding the minimum route dependencies and Problem Details boundary:

```text
uv run pytest tests/api/test_authorization.py -q  # 13 passed
uv run pytest tests/api -q                        # 55 passed
uv run pytest -q --disable-warnings               # 180 passed
uv run ruff check src tests                       # passed
uv run ruff format --check src tests              # passed
git diff --check                                  # passed
```

The focused tests cover viewer, owner, auditor, risk approver, service
principals, allowed and denied capabilities, cross-organization resources,
SBOM metadata, and the explicit test bypass. The full API suite preserves the
existing test-only bypass behavior.

## Implementation

- Added `require_organization` and `require_capability` dependencies in
  `src/vulnops/auth/dependencies.py`. Organization membership is evaluated
  before capability checks, so an authenticated principal outside the path
  organization receives `resource_not_found` rather than a capability leak.
- The test bypass is recognized only when the request principal is the
  application-created test principal and the startup-validated bypass setting
  is enabled. A real token containing `*` in its organization claim is never a
  global principal; wildcard claims and wildcard path organizations are
  rejected.
- Added explicit route capabilities:
  - case reads, histories, and allowed transitions: `case:read`
  - case creation and transitions: `case:write`
  - risk decision requests: `risk:request`
  - verification submission: `verification:write`
  - SBOM submission and metadata reads: `sbom:write` and `sbom:read`
- Updated case and SBOM resource checks to return the safe authorization
  not-found category for missing or cross-organization resources, including
  the previously unguarded allowed-transitions lookup.
- Added a top-level `AuthorizationError` Problem Details handler in
  `src/vulnops/main.py`; this small application-boundary change is necessary
  because FastAPI's default `HTTPException` response nests `detail` instead of
  emitting the required `code`, `status`, and `type` fields at the top level.
- Domain services remain unaware of FastAPI, bearer tokens, and principal
  parsing. Trusted workflow actor binding and a separate risk approval action
  remain Task 5 work.

## Self-review

- Same-organization principals without the route capability receive `403
  insufficient_permission` without entering the domain service.
- Principals outside the requested organization receive `404
  resource_not_found` before capability evaluation.
- A principal belonging to the requested organization that names a resource
  owned by another organization receives the same safe `404` response.
- Collection reads for a trusted organization remain valid and return an empty
  collection when that organization has no matching records; this does not
  disclose another organization's records.
- Existing HTTP validation and concurrency errors remain unchanged after the
  authorization dependency succeeds.

## Concerns / follow-up

1. Task 5 must bind transition and risk-request actors to `Principal`, reject
   client-supplied approval identity, and add the separate `risk:approve`
   endpoint. This task intentionally does not change workflow actor fields.
2. The explicit test bypass remains a test-fixture mechanism. Task 8 still
   needs an authenticated test issuer for Docker, OpenAPI, and browser flows.
3. The test environment emits the existing Starlette/httpx deprecation
   warnings; they are unrelated to the authorization behavior.

## Fix round 1: resource ordering and literal route matrix

### RED

The fix-round tests were added before changing the route implementation and
were run against the first Task 4 commit:

```text
uv run pytest tests/api/test_authorization.py -q
7 failed, 79 passed
```

All seven failures were the cross-organization ordering cases. A principal
belonging to the path organization but lacking the operation capability got a
403 before the endpoint loaded a case, and malformed transition/risk/
verification bodies therefore also failed with 403 instead of the required
404. The new test file also contains a literal 11-route by six-principal
expected-status matrix; it exposed no unrelated baseline failures.

### GREEN

The implementation was then changed so resource routes perform path
organization membership, resource ownership, and capability checks in that
order. Request JSON, If-Match parsing, and domain service mutation now happen
only after both authorization checks pass.

```text
uv run pytest tests/api/test_authorization.py -q  # 86 passed
uv run pytest tests/api -q                        # 128 passed
uv run pytest -q --disable-warnings               # 253 passed
uv run ruff check src tests                       # passed
uv run ruff format --check src tests              # passed
git diff --check                                  # passed
```

The matrix has one explicit expected status for each of the 66
route/principal combinations. It covers all 11 current routes: case create,
case list/detail, allowed transitions, transition, risk request/history,
verification submit/history, and SBOM submit/detail. Collection-level
cross-organization case creation/list and SBOM submission are explicitly
asserted as 404, while resource routes use valid fixture IDs and malformed
cross-organization bodies to prove no validation or concurrency detail leaks.

### Fix-round self-review

- `require_capability` remains the correct dependency for collection routes,
  where organization membership precedes capability and there is no resource
  to resolve.
- Resource routes use `require_organization`, then resolve and compare the
  actual case/SBOM organization, then call `authorize_capability`; FastAPI and
  token parsing remain outside domain services.
- The allowed-transitions route now performs the same ownership check as case
  detail, and SBOM detail resolves the organization-filtered record before
  checking `sbom:read`.
- The explicit test bypass still permits only its application-created test
  principal to exercise all organizations; real wildcard claims remain
  denied.

### Fix-round concerns

1. The separate Task 5 actor-binding and risk-approval work remains pending;
   this round intentionally changes authorization ordering only.
2. The full suite still reports the pre-existing Starlette/httpx deprecation
   warnings when warnings are enabled.

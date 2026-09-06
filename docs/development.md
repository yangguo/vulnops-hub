# Development Guide

> **Document status:** Current as-built workflow for commit `ac51721` and later.
> When this guide conflicts with a historical plan under `docs/plans/` or
> `docs/superpowers/`, this guide, the checked-in OpenAPI file, and executable
> tests describe the current repository.

## 1. Supported toolchain

- Python 3.11 or newer; CI currently uses Python 3.12.
- `uv` for Python dependency and virtual-environment management.
- Node.js 22.22.2 and pnpm 9.15.0 for `frontend/`.
- Docker with Compose for the multi-service evaluation stack.

The Node version is pinned in `.nvmrc` and `.node-version`. The frontend uses
`engine-strict=true`, so an unsupported Node or pnpm version fails during
installation instead of producing misleading test failures.

~~~bash
nvm use                    # or use the version manager of your choice
corepack enable
corepack prepare pnpm@9.15.0 --activate
make install
make frontend-install
~~~

## 2. Repository layout

| Path | Responsibility |
| --- | --- |
| `src/vulnops/api/` | FastAPI routers and HTTP serialization |
| `src/vulnops/assets/` | Canonical asset identity and alias reconciliation |
| `src/vulnops/sbom/` | CycloneDX/SPDX parsing and idempotent ingestion |
| `src/vulnops/intelligence/` | KEV, EPSS, OSV, and Vulnerability-Lookup adapters |
| `src/vulnops/integrations/` | DefectDojo and Wazuh evidence bridges |
| `src/vulnops/matching/` | Deterministic and candidate matching |
| `src/vulnops/risk/` | Versioned risk policy and simulation |
| `src/vulnops/cases/` | Case state machine, SLA, decisions, and verification |
| `src/vulnops/workers/` | Queue-driven ingestion worker |
| `src/vulnops/db/` | SQLAlchemy models and Alembic migrations |
| `frontend/src/` | Vue console, typed API client, stores, views, and components |
| `openapi/openapi.yaml` | Checked-in HTTP contract used by the frontend |
| `tests/` | Unit, API, integration, contract, fixture E2E tests |

## 3. Local development

The API uses `vulnops.db` when `DATABASE_URL` is unset. This is suitable only
for disposable local evaluation.

~~~bash
make install
make migrate
make dev
~~~

In a second terminal:

~~~bash
make frontend-install
make frontend-dev
~~~

Open `http://localhost:5173`; Vite proxies `/api`, `/health`, `/docs`, and
`/openapi.json` to `http://127.0.0.1:8000`. To evaluate the production-shaped
SPA locally, run `make frontend-build` and start the API; FastAPI serves
`frontend/dist` from `/`.

If a persistent development database produces migration or fixture conflicts,
use `make clean && make migrate`. Never use this reset against shared data.

## 4. Verification commands

Before committing backend changes:

~~~bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest -q
~~~

Before committing frontend changes:

~~~bash
cd frontend
pnpm lint
pnpm typecheck
pnpm test
pnpm build
~~~

The CI workflow additionally validates a fresh Alembic migration, the checked
OpenAPI contract, the Docker image and health probes, and a Playwright browser
smoke test. A local pass is not evidence that a remote run passed; link the
exact GitHub Actions run when recording release evidence.

## 5. Database migrations

Create migrations only from a database at the current Alembic head:

~~~bash
make migrate
make migrate-new             # prompts for the migration message
uv run alembic check
~~~

Verify from a fresh database before review:

~~~bash
verify_dir=$(mktemp -d)
DATABASE_URL="sqlite:///$verify_dir/verify.db" uv run alembic upgrade head
DATABASE_URL="sqlite:///$verify_dir/verify.db" uv run alembic check
~~~

Do not edit or reorder an applied migration. Add a new revision and document
its upgrade, compatibility, and rollback posture.

## 6. OpenAPI workflow

`openapi/openapi.yaml` is the machine-readable contract for implemented HTTP
routes. `docs/api.md` also contains target-state contracts and is not a
substitute for the checked specification.

After an API schema or route change:

1. Update or add API and contract tests.
2. Regenerate `openapi/openapi.yaml` from `create_app()` using the repository's
   established generation command in the relevant implementation plan.
3. Run `uv run pytest tests/contract -q`.
4. Run `cd frontend && pnpm openapi`.
5. Review both generated diffs and run frontend type checking.

Never hand-edit only the generated TypeScript declarations while leaving the
server contract unchanged.

## 7. Change workflow

- Add a failing test before changing behavior.
- Keep schema, migration, API, UI, and documentation changes in the same
  scoped series when they describe one feature.
- Preserve organization scoping and return `404` for cross-organization case
  reads to avoid resource disclosure.
- Keep ingestion replay-safe and persist cursors only after durable work.
- Do not allow candidate matches or missing scan output to create/close cases.
- Add an ADR for system-of-record, identity, lifecycle, licensing, or topology
  changes.

## 8. Current limitations

The technical preview has no enforced OIDC/RBAC, no production certification,
and no first-adopter integration evidence. Source-health and coverage-gap APIs,
external ticket/notification projections, CSV/CMDB import, and restore/replay
drills remain open. See `docs/acceptance-matrix.md` for test-level status and
`docs/mvp-roadmap.md` for milestone scope.

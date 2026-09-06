import { defineConfig } from '@playwright/test'

const apiUrl = process.env.E2E_API_URL || 'http://127.0.0.1:8010'
const oidcIssuer = process.env.E2E_OIDC_ISSUER || 'http://127.0.0.1:9000'
const oidcAudience = process.env.E2E_OIDC_AUDIENCE || 'vulnops-api'
const oidcPort = new URL(oidcIssuer).port || '9000'

export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  // Components mark transition buttons with `data-test`, not `data-testid`.
  use: { baseURL: 'http://127.0.0.1:4173', testIdAttribute: 'data-test' },
  webServer: [
    {
      command: `uv run python tests/e2e/oidc_test_issuer.py --host 127.0.0.1 --port ${oidcPort}`,
      url: `${oidcIssuer}/health/live`,
      reuseExistingServer: false,
      cwd: '..',
    },
    {
      command:
        'rm -f /tmp/vulnops-e2e.db && uv run alembic -c alembic.ini upgrade head && uv run uvicorn vulnops.main:app --port 8010',
      url: `${apiUrl}/health/live`,
      reuseExistingServer: false,
      cwd: '..',
      env: {
        DATABASE_URL: 'sqlite:////tmp/vulnops-e2e.db',
        ENVIRONMENT: 'test',
        AUTH_TEST_BYPASS_ENABLED: 'false',
        OIDC_ISSUER_URL: oidcIssuer,
        OIDC_AUDIENCE: oidcAudience,
      },
    },
    {
      // --host 127.0.0.1: vite preview binds `localhost`, which on macOS resolves
      // to ::1 (IPv6) only, while Playwright probes/connects over 127.0.0.1.
      command: 'corepack pnpm --config.engine-strict=false preview --port 4173 --strictPort --host 127.0.0.1',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: false,
      env: { VITE_API_TARGET: apiUrl },
    },
  ],
})

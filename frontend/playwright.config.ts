import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  // Components mark transition buttons with `data-test`, not `data-testid`.
  use: { baseURL: 'http://127.0.0.1:4173', testIdAttribute: 'data-test' },
  webServer: [
    {
      command: 'rm -f /tmp/vulnops-e2e.db && uv run uvicorn vulnops.main:app --port 8010',
      url: 'http://127.0.0.1:8010/health/live',
      reuseExistingServer: false,
      cwd: '..',
      env: { DATABASE_URL: 'sqlite:////tmp/vulnops-e2e.db' },
    },
    {
      // --host 127.0.0.1: vite preview binds `localhost`, which on macOS resolves
      // to ::1 (IPv6) only, while Playwright probes/connects over 127.0.0.1.
      command: 'pnpm preview --port 4173 --strictPort --host 127.0.0.1',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: false,
      env: { VITE_API_TARGET: 'http://127.0.0.1:8010' },
    },
  ],
})

# Frontend Remediation Ops Console Implementation Plan

> **Execution status:** Completed on 2026-09-06. Implemented by commits
> `c48e75c` through `5bf2b88` and released to `main` with `ac51721`. The
> unchecked boxes below preserve the original TDD execution sequence and are
> not the current project backlog. Authentication remains a separate next
> slice documented in `docs/plans/2026-09-06-oidc-rbac.md`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Vue 3 + Element Plus remediation ops console (dashboard, case list, case detail with lifecycle actions, SBOM submit) served by the existing FastAPI app from a single container.

**Architecture:** SPA in `frontend/` talking to the existing REST API through a typed fetch client; Pinia stores hold org/list/detail state; FastAPI serves `frontend/dist` with SPA fallback so deployment stays single-container. Spec: `docs/superpowers/specs/2026-09-05-frontend-console-design.md`.

**Tech Stack:** Vue 3 + Vite + TypeScript + Element Plus + Pinia + Vue Router + ECharts; Vitest + @vue/test-utils; Playwright; pnpm 9.

## Global Constraints

- **Prerequisite:** the backend plan `2026-09-05-backend-case-read-endpoints.md` must be merged first — Task 2 generates types from `openapi/openapi.yaml`, which includes the three new read endpoints.
- No login/auth in the UI (spec §2). Do not add auth guards, login routes, or token storage.
- Chinese UI copy (spec §2: 文案中文先行). Status/priority values are the backend's English enums (`new`, `triage`, `P1`, …) — never translate enum values sent to the API.
- All API calls go through `frontend/src/api/client.ts` — components never call `fetch` directly.
- Optimistic locking: every transition sends `If-Match: "<version>"` from the loaded detail; a 412 must trigger the refresh-confirm flow (Task 5), never a raw error toast.
- Node 22, pnpm 9 (`"packageManager": "pnpm@9.15.0"` — pnpm 10's build-approval prompt breaks CI).
- pnpm commands run inside `frontend/` unless a path says otherwise; backend commands run at repo root.

---

### Task 1: Scaffold + app shell + Makefile targets

**Files:**
- Create: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`, `frontend/tsconfig.node.json`, `frontend/index.html`, `frontend/src/main.ts`, `frontend/src/App.vue`, `frontend/src/router.ts`, `frontend/src/views/PlaceholderView.vue`, `frontend/src/env.d.ts`, `frontend/eslint.config.js`, `frontend/.gitignore`
- Modify: `Makefile`

**Interfaces:**
- Produces: runnable app shell (`pnpm dev` → sidebar layout with 3 menu items + disabled future items); `pnpm test` / `pnpm lint` / `pnpm typecheck` / `pnpm build` all pass; router paths `/`, `/cases`, `/cases/:id`, `/sboms` used by all later tasks.

- [ ] **Step 1: Create `frontend/package.json`**

```json
{
  "name": "vulnops-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "packageManager": "pnpm@9.15.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "lint": "eslint .",
    "typecheck": "vue-tsc --noEmit",
    "openapi": "openapi-typescript ../openapi/openapi.yaml -o src/api/schema.d.ts"
  },
  "dependencies": {
    "echarts": "^5.5.0",
    "element-plus": "^2.8.0",
    "pinia": "^2.2.0",
    "vue": "^3.5.0",
    "vue-router": "^4.4.0"
  },
  "devDependencies": {
    "@eslint/js": "^9.10.0",
    "@playwright/test": "^1.47.0",
    "@vitejs/plugin-vue": "^5.1.0",
    "@vue/test-utils": "^2.4.0",
    "eslint": "^9.10.0",
    "eslint-plugin-vue": "^9.28.0",
    "jsdom": "^25.0.0",
    "openapi-typescript": "^7.4.0",
    "typescript": "^5.5.0",
    "typescript-eslint": "^8.6.0",
    "vite": "^5.4.0",
    "vitest": "^2.1.0",
    "vue-eslint-parser": "^9.4.0",
    "vue-tsc": "^2.1.0"
  }
}
```

- [ ] **Step 2: Create build/config files**

`frontend/vite.config.ts`:

```ts
/// <reference types="vitest" />
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const apiTarget = process.env.VITE_API_TARGET || 'http://127.0.0.1:8000'

const proxy = {
  '/api': { target: apiTarget, changeOrigin: true },
  '/health': { target: apiTarget, changeOrigin: true },
  '/docs': { target: apiTarget, changeOrigin: true },
  '/openapi.json': { target: apiTarget, changeOrigin: true },
}

export default defineConfig({
  plugins: [vue()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  test: { environment: 'jsdom', globals: true },
})
```

`frontend/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "jsx": "preserve",
    "resolveJsonModule": true,
    "esModuleInterop": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "skipLibCheck": true,
    "noEmit": true,
    "types": ["vitest/globals"]
  },
  "include": ["src/**/*.ts", "src/**/*.vue", "env.d.ts"]
}
```

`frontend/tsconfig.node.json`:

```json
{
  "compilerOptions": {
    "composite": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "types": ["node"]
  },
  "include": ["vite.config.ts", "eslint.config.js"]
}
```

(`types: ["node"]` needs `@types/node` — add `"@types/node": "^22.0.0"` to devDependencies in Step 1 if `pnpm typecheck` complains about `process` in vite.config.ts.)

`frontend/env.d.ts`:

```ts
/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}
```

`frontend/eslint.config.js`:

```js
import js from '@eslint/js'
import pluginVue from 'eslint-plugin-vue'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/', 'src/api/schema.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...pluginVue.configs['flat/recommended'],
  {
    files: ['**/*.vue'],
    languageOptions: { parserOptions: { parser: tseslint.parser } },
  },
  {
    rules: {
      'vue/multi-word-component-names': 'off',
    },
  },
)
```

`frontend/.gitignore`:

```
dist/
node_modules/
playwright-report/
test-results/
```

`frontend/index.html`:

```html
<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>VulnOps Hub — 整改运营控制台</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

- [ ] **Step 3: Create app entry, router, shell**

`frontend/src/main.ts`:

```ts
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import 'element-plus/dist/index.css'
import App from './App.vue'
import { router } from './router'

createApp(App).use(createPinia()).use(router).use(ElementPlus, { locale: zhCn }).mount('#app')
```

`frontend/src/router.ts`:

```ts
import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: () => import('./views/DashboardView.vue') },
    { path: '/cases', component: () => import('./views/CaseListView.vue') },
    { path: '/cases/:id', component: () => import('./views/CaseDetailView.vue') },
    { path: '/sboms', component: () => import('./views/SbomSubmitView.vue') },
  ],
})
```

Router imports four views that do not exist yet — create them all now as the same placeholder so the app compiles; later tasks replace their contents one by one.

`frontend/src/views/PlaceholderView.vue` (create 4 copies: `DashboardView.vue`, `CaseListView.vue`, `CaseDetailView.vue`, `SbomSubmitView.vue`):

```vue
<template>
  <el-empty description="建设中" />
</template>
```

`frontend/src/App.vue`:

```vue
<template>
  <el-container class="app-shell">
    <el-aside width="220px" class="app-aside">
      <div class="app-logo">🛡 VulnOps Hub</div>
      <el-menu router :default-active="route.path" class="app-menu">
        <el-menu-item index="/">📊 看板</el-menu-item>
        <el-menu-item index="/cases">📋 工单</el-menu-item>
        <el-menu-item index="/sboms">📦 SBOM 提交</el-menu-item>
        <el-menu-item-group title="未来模块">
          <el-menu-item index="/assets" disabled>🏷 资产</el-menu-item>
          <el-menu-item index="/intel" disabled>🛰 情报</el-menu-item>
        </el-menu-item-group>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="app-header">
        <span class="app-title">{{ pageTitle }}</span>
        <span class="app-env">内网评估版 · 未启用认证</span>
      </el-header>
      <el-main><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const pageTitle = computed(() => {
  if (route.path === '/') return '看板'
  if (route.path.startsWith('/cases/')) return '工单详情'
  if (route.path === '/cases') return '整改工单'
  if (route.path === '/sboms') return 'SBOM 提交'
  return 'VulnOps Hub'
})
</script>

<style>
body { margin: 0; font-family: system-ui, sans-serif; }
.app-shell { height: 100vh; }
.app-aside { border-right: 1px solid var(--el-border-color-light); }
.app-logo { font-weight: 700; font-size: 16px; padding: 18px 20px; }
.app-menu { border-right: none; }
.app-header {
  display: flex; align-items: center; justify-content: space-between;
  border-bottom: 1px solid var(--el-border-color-light);
}
.app-title { font-size: 16px; font-weight: 600; }
.app-env { color: var(--el-color-warning); font-size: 12px; }
</style>
```

- [ ] **Step 4: Install dependencies and verify the toolchain**

```bash
cd frontend && pnpm install
pnpm build && pnpm typecheck && pnpm lint && pnpm test
```

Expected: build emits `dist/`, typecheck/lint clean, `pnpm test` prints "No test files found" and **exits 0** (add `"test": "vitest run --passWithNoTests"` to the `test` script in `package.json` if it exits 1 — later tasks add real tests).

- [ ] **Step 5: Manual smoke with the backend**

```bash
uv run uvicorn vulnops.main:app --port 8000   # repo root, separate terminal
cd frontend && pnpm dev                        # open http://localhost:5173
```

Expected: sidebar renders; clicking 工单 shows the placeholder. (Element Plus menu items navigate via `router` mode.)

- [ ] **Step 6: Add Makefile targets and commit**

Append to `Makefile` (keep `.PHONY` line updated to include the new targets):

```make
frontend-install:
	cd frontend && pnpm install

frontend-dev:
	cd frontend && pnpm dev

frontend-build:
	cd frontend && pnpm build

frontend-test:
	cd frontend && pnpm test
```

```bash
git add frontend Makefile
git commit -m "feat(frontend): Vue 3 + Element Plus console scaffold"
```

---

### Task 2: API client + org store + generated types

**Files:**
- Create: `frontend/src/api/schema.d.ts` (generated), `frontend/src/api/client.ts`, `frontend/src/api/types.ts`, `frontend/src/stores/org.ts`
- Test: `frontend/src/api/client.test.ts`, `frontend/src/stores/org.test.ts`

**Interfaces:**
- Consumes: `openapi/openapi.yaml` including the backend plan's endpoints (list cases, risk-decisions, verifications).
- Produces (used by Tasks 3–7): `api.types.CaseDetail`, `CaseListResponse`, `RiskDecisionItem`, `VerificationItem`; `apiClient.{listCases(org, qs), getCase(org, id), getAllowed(org, id), transition(org, id, version, target, actor, reason), createRiskDecision(org, id, payload), submitVerification(org, id, payload), submitSbom(org, body, idempotencyKey), getHealthLive()}`; `ApiError{status, code, message}`; `useOrgStore` with `org: string`, `setOrg(org: string)`.

- [ ] **Step 1: Generate the typed schema**

```bash
cd frontend && pnpm openapi && head -20 src/api/schema.d.ts
```

Expected: `src/api/schema.d.ts` exists and mentions `risk-decisions`. Commit it (checked-in types keep CI deterministic).

- [ ] **Step 2: Write the failing client tests**

`frontend/src/api/client.test.ts`:

```ts
import { describe, expect, it, vi, afterEach } from 'vitest'
import { apiClient, ApiError } from './client'

afterEach(() => vi.unstubAllGlobals())

describe('apiClient error normalization', () => {
  it('maps Problem Details to ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(
        JSON.stringify({ type: 'x', title: 'Invalid Transition', status: 422, code: 'invalid_transition', detail: 'transition new -> closed not allowed' }),
        { status: 422 },
      )),
    )
    await expect(apiClient.getCase('org', 'c1')).rejects.toMatchObject({
      status: 422,
      code: 'invalid_transition',
      message: 'transition new -> closed not allowed',
    })
  })

  it('retries once on network failure then throws network_error', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('failed'))
    vi.stubGlobal('fetch', fetchMock)
    await expect(apiClient.getCase('org', 'c1')).rejects.toMatchObject({
      status: 0,
      code: 'network_error',
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('sends If-Match header on transition', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ id: 'c1', status: 'triage', version: 2, etag: '"2"' }),
      { status: 200 },
    ))
    vi.stubGlobal('fetch', fetchMock)
    await apiClient.transition('org', 'c1', 1, 'triage', 'alice', 'r')
    const [, init] = fetchMock.mock.calls[0]
    expect(init.headers['If-Match']).toBe('"1"')
  })
})
```

`frontend/src/stores/org.test.ts`:

```ts
import { describe, expect, it, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useOrgStore } from './org'

describe('orgStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('defaults to org-demo', () => {
    expect(useOrgStore().org).toBe('org-demo')
  })

  it('persists switched org', () => {
    useOrgStore().setOrg('acme')
    expect(localStorage.getItem('vulnops.org')).toBe('acme')
    expect(useOrgStore().org).toBe('acme')
  })
})
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd frontend && pnpm test`
Expected: FAIL — modules `./client` / `./org` do not exist.

- [ ] **Step 4: Implement `types.ts`, `client.ts`, `org.ts`**

`frontend/src/api/types.ts` (response shapes extracted from the generated schema so stores/views get short names):

```ts
import type { paths } from './schema'

type Json<T> = T extends { content: { 'application/json': infer B } } ? B : never

export type CaseDetail = Json<
  paths['/api/v1/organizations/{org_id}/cases/{case_id}']['get']['responses']['200']
>
export type TransitionResponse = Json<
  paths['/api/v1/organizations/{org_id}/cases/{case_id}/transitions']['post']['responses']['200']
>
export type AllowedTransitionsResponse = Json<
  paths['/api/v1/organizations/{org_id}/cases/{case_id}/allowed-transitions']['get']['responses']['200']
>

export interface CaseListResponse {
  items: CaseDetail[]
  total: number
  page: number
  page_size: number
}
export interface RiskDecisionItem {
  id: string
  case_id: string
  type: string
  status: string
  scope_exposure_ids: string[]
  reason: string
  compensating_controls: string[]
  evidence_ids: string[]
  requested_by: string
  approver: string | null
  approver_role: string | null
  expires_at: string | null
  created_at: string | null
}
export interface VerificationItem {
  id: string
  case_id: string
  method: string
  asserted_result: string | null
  evidence_ids: string[]
  coverage: Record<string, unknown>
  status: string
  created_at: string | null
}
export interface RiskDecisionsResponse { items: RiskDecisionItem[] }
export interface VerificationsResponse { items: VerificationItem[] }
```

`frontend/src/api/client.ts`:

```ts
import type {
  AllowedTransitionsResponse,
  CaseDetail,
  CaseListResponse,
  RiskDecisionItem,
  RiskDecisionsResponse,
  TransitionResponse,
  VerificationItem,
  VerificationsResponse,
} from './types'

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message)
  }
}

async function request<T>(path: string, init: RequestInit = {}, allowRetry = true): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(path, init)
  } catch {
    if (allowRetry) return request<T>(path, init, false)
    throw new ApiError(0, 'network_error', '无法连接服务器，请检查后端是否运行')
  }
  if (resp.status === 204) return undefined as T
  const body = resp.headers.get('content-type')?.includes('json')
    ? await resp.json().catch(() => null)
    : null
  if (!resp.ok) {
    const raw = body && (body.detail ?? body.title) ? body.detail ?? body.title : resp.statusText
    const message = typeof raw === 'string' ? raw : JSON.stringify(raw)
    const code = body?.code ?? 'error'
    throw new ApiError(resp.status, code, message)
  }
  return body as T
}

function jsonInit(method: string, payload: unknown, headers: Record<string, string> = {}): RequestInit {
  return {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(payload),
  }
}

export const apiClient = {
  listCases(org: string, query = ''): Promise<CaseListResponse> {
    return request(`/api/v1/organizations/${org}/cases${query}`)
  },
  getCase(org: string, caseId: string): Promise<CaseDetail> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}`)
  },
  getAllowed(org: string, caseId: string): Promise<AllowedTransitionsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/allowed-transitions`)
  },
  transition(
    org: string,
    caseId: string,
    version: number,
    target: string,
    actor: string,
    reason?: string,
  ): Promise<TransitionResponse> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/transitions`,
      jsonInit('POST', { target, actor, reason }, { 'If-Match': `"${version}"` }),
    )
  },
  createRiskDecision(org: string, caseId: string, payload: Record<string, unknown>): Promise<RiskDecisionItem> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/risk-decisions`,
      jsonInit('POST', payload),
    )
  },
  listRiskDecisions(org: string, caseId: string): Promise<RiskDecisionsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/risk-decisions`)
  },
  submitVerification(org: string, caseId: string, payload: Record<string, unknown>): Promise<VerificationItem> {
    return request(
      `/api/v1/organizations/${org}/cases/${caseId}/verifications`,
      jsonInit('POST', payload),
    )
  },
  listVerifications(org: string, caseId: string): Promise<VerificationsResponse> {
    return request(`/api/v1/organizations/${org}/cases/${caseId}/verifications`)
  },
  submitSbom(org: string, body: unknown, idempotencyKey: string): Promise<Record<string, unknown>> {
    return request(
      `/api/v1/organizations/${org}/sboms`,
      jsonInit('POST', body, { 'Idempotency-Key': idempotencyKey }),
    )
  },
  getHealthLive(): Promise<{ service: string; version: string }> {
    return request('/health/live')
  },
}
```

`frontend/src/stores/org.ts`:

```ts
import { defineStore } from 'pinia'

const STORAGE_KEY = 'vulnops.org'

export const useOrgStore = defineStore('org', {
  state: () => ({ org: localStorage.getItem(STORAGE_KEY) || 'org-demo' }),
  actions: {
    setOrg(org: string) {
      this.org = org
      localStorage.setItem(STORAGE_KEY, org)
    },
  },
})
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd frontend && pnpm test && pnpm typecheck && pnpm lint`
Expected: PASS (client 3 tests, org 2 tests), typecheck/lint clean.

- [ ] **Step 5b: Wire the org switcher into the global header (spec §5.1)**

In `frontend/src/App.vue`, replace the header block with:

```html
      <el-header class="app-header">
        <span class="app-title">{{ pageTitle }}</span>
        <div class="header-right">
          <el-select
            :model-value="orgStore.org"
            filterable
            allow-create
            default-first-option
            placeholder="组织"
            style="width: 160px"
            @change="switchOrg"
          >
            <el-option label="org-demo" value="org-demo" />
          </el-select>
          <span class="app-env">内网评估版 · 未启用认证</span>
        </div>
      </el-header>
```

Extend the script setup:

```ts
import { useOrgStore } from './stores/org'

const orgStore = useOrgStore()

function switchOrg(org: string) {
  orgStore.setOrg(org)
  window.location.reload() // MVP: 切换组织后整页刷新，重取所有数据
}
```

Add to the styles: `.header-right { display: flex; align-items: center; gap: 12px; }`.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api frontend/src/stores/org.ts frontend/src/App.vue
git commit -m "feat(frontend): typed API client, org store, org switcher"
```

---

### Task 3: Case list view + casesStore

**Files:**
- Create: `frontend/src/stores/cases.ts`, `frontend/src/components/PriorityTag.vue`, `frontend/src/components/StatusTag.vue`, `frontend/src/components/SlaBadge.vue`, `frontend/src/views/CaseListView.vue` (replace placeholder)
- Test: `frontend/src/stores/cases.test.ts`, `frontend/src/components/SlaBadge.test.ts`

**Interfaces:**
- Consumes: `apiClient.listCases`, `useOrgStore`, `CaseDetail`/`CaseListResponse` (Task 2).
- Produces: `useCasesStore` with state `{items: CaseDetail[], total, page, pageSize, loading, filters: {status, priority, ownerTeam, slaBreached}}` and actions `fetch()`, `resetFilters()`; shared presentational components `PriorityTag`/`StatusTag`/`SlaBadge` (reused by Task 4/6); route `/cases` shows the live list.

- [ ] **Step 1: Write the failing tests**

`frontend/src/stores/cases.test.ts`:

```ts
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useCasesStore } from './cases'
import { useOrgStore } from './org'
import { apiClient } from '../api/client'
import type { CaseDetail } from '../api/types'

vi.mock('../api/client', () => ({ apiClient: { listCases: vi.fn() } }))

const caseOf = (id: string, over: Partial<CaseDetail> = {}): CaseDetail =>
  ({
    id,
    case_key: 'CASE-X',
    title: 't',
    status: 'new',
    priority: 'P2',
    owner_team: 'platform',
    assignee: null,
    organization_id: 'org-demo',
    policy_version: null,
    version: 1,
    etag: '"1"',
    due_at: null,
    exposures: [],
    sla_breached: false,
    closure_reason: null,
    created_at: '2026-09-05T00:00:00+00:00',
    updated_at: '2026-09-05T00:00:00+00:00',
    ...over,
  }) as CaseDetail

describe('casesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.mocked(apiClient.listCases).mockReset()
  })

  it('builds querystring from filters and stores the page', async () => {
    vi.mocked(apiClient.listCases).mockResolvedValue({
      items: [caseOf('c1')], total: 1, page: 2, page_size: 20,
    })
    const store = useCasesStore()
    useOrgStore().setOrg('acme')
    store.filters.status = 'triage'
    store.filters.slaBreached = true
    store.page = 2
    await store.fetch()
    expect(apiClient.listCases).toHaveBeenCalledWith(
      'acme',
      '?status=triage&sla_breached=true&page=2&page_size=20&sort=-created_at',
    )
    expect(store.items).toHaveLength(1)
    expect(store.total).toBe(1)
    expect(store.loading).toBe(false)
  })

  it('omits empty filters', async () => {
    vi.mocked(apiClient.listCases).mockResolvedValue({
      items: [], total: 0, page: 1, page_size: 20,
    })
    await useCasesStore().fetch()
    expect(apiClient.listCases).toHaveBeenCalledWith('org-demo', '?page=1&page_size=20&sort=-created_at')
  })
})
```

`frontend/src/components/SlaBadge.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import SlaBadge from './SlaBadge.vue'

describe('SlaBadge', () => {
  it('renders remaining time for future due dates', () => {
    const due = new Date(Date.now() + 2 * 24 * 3600 * 1000).toISOString()
    const w = mount(SlaBadge, { props: { dueAt: due, breached: false } })
    expect(w.text()).toContain('剩')
    expect(w.classes()).not.toContain('sla-breached')
  })

  it('renders breached state in red', () => {
    const w = mount(SlaBadge, { props: { dueAt: new Date(Date.now() - 1000).toISOString(), breached: true } })
    expect(w.text()).toContain('已超时')
    expect(w.classes()).toContain('sla-breached')
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && pnpm test`
Expected: FAIL — stores/cases and SlaBadge missing.

- [ ] **Step 3: Implement the shared components**

`frontend/src/components/PriorityTag.vue`:

```vue
<template>
  <el-tag :type="type" effect="dark" size="small">{{ priority }}</el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ priority: string }>()
const type = computed(() => {
  if (props.priority === 'P0' || props.priority === 'P1') return 'danger'
  if (props.priority === 'P2') return 'warning'
  return 'info'
})
</script>
```

`frontend/src/components/StatusTag.vue`:

```vue
<template>
  <el-tag :type="map[status] ?? 'info'" size="small">{{ label }}</el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string }>()

const LABELS: Record<string, string> = {
  new: '新建',
  triage: '分诊',
  assigned: '已分派',
  in_progress: '整改中',
  awaiting_verification: '待复测',
  closed: '已关闭',
  risk_accepted: '风险已接受',
  not_applicable: '不适用',
  reopened: '已重开',
}
const TYPES: Record<string, string> = {
  new: 'info',
  triage: 'warning',
  assigned: 'primary',
  in_progress: 'primary',
  awaiting_verification: 'warning',
  closed: 'success',
  risk_accepted: 'danger',
  not_applicable: 'info',
  reopened: 'danger',
}
const label = computed(() => LABELS[props.status] ?? props.status)
const map = TYPES
</script>
```

`frontend/src/components/SlaBadge.vue`:

```vue
<template>
  <span class="sla-badge" :class="{ 'sla-breached': breached }">
    {{ breached ? '⚠ 已超时' : `⏱ 剩 ${remaining}` }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ dueAt: string | null; breached: boolean }>()

const remaining = computed(() => {
  if (!props.dueAt) return '无 SLA'
  const ms = new Date(props.dueAt).getTime() - Date.now()
  if (ms <= 0) return '已超时'
  const hours = Math.floor(ms / 3600000)
  if (hours < 48) return `${hours}h`
  return `${Math.floor(hours / 24)}d${hours % 24}h`
})
</script>

<style scoped>
.sla-badge { font-size: 12px; color: var(--el-color-success); }
.sla-badge.sla-breached { color: var(--el-color-danger); font-weight: 600; }
</style>
```

- [ ] **Step 4: Implement casesStore + list view**

`frontend/src/stores/cases.ts`:

```ts
import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import type { CaseDetail } from '../api/types'
import { useOrgStore } from './org'

export const useCasesStore = defineStore('cases', {
  state: () => ({
    items: [] as CaseDetail[],
    total: 0,
    page: 1,
    pageSize: 20,
    sort: '-created_at',
    loading: false,
    filters: { status: '', priority: '', ownerTeam: '', slaBreached: false },
  }),
  actions: {
    async fetch() {
      this.loading = true
      try {
        const org = useOrgStore().org
        const qs = new URLSearchParams()
        if (this.filters.status) qs.set('status', this.filters.status)
        if (this.filters.priority) qs.set('priority', this.filters.priority)
        if (this.filters.ownerTeam) qs.set('owner_team', this.filters.ownerTeam)
        if (this.filters.slaBreached) qs.set('sla_breached', 'true')
        qs.set('page', String(this.page))
        qs.set('page_size', String(this.pageSize))
        qs.set('sort', this.sort)
        const data = await apiClient.listCases(org, `?${qs.toString()}`)
        this.items = data.items
        this.total = data.total
      } finally {
        this.loading = false
      }
    },
    resetFilters() {
      this.filters = { status: '', priority: '', ownerTeam: '', slaBreached: false }
      this.page = 1
    },
  },
})
```

`frontend/src/views/CaseListView.vue`:

```vue
<template>
  <div class="filters">
    <el-select v-model="store.filters.status" placeholder="状态" clearable style="width: 150px" @change="reload">
      <el-option v-for="(label, value) in STATUS_OPTIONS" :key="value" :label="label" :value="value" />
    </el-select>
    <el-select v-model="store.filters.priority" placeholder="优先级" clearable style="width: 120px" @change="reload">
      <el-option v-for="p in ['P0', 'P1', 'P2', 'P3', 'P4']" :key="p" :label="p" :value="p" />
    </el-select>
    <el-input
      v-model="store.filters.ownerTeam"
      placeholder="归属团队"
      clearable
      style="width: 160px"
      @change="reload"
    />
    <el-checkbox v-model="store.filters.slaBreached" label="仅看 SLA 超时" @change="reload" />
    <el-select v-model="store.sort" style="width: 140px" @change="reload">
      <el-option label="最近创建" value="-created_at" />
      <el-option label="最早到期" value="due_at" />
      <el-option label="优先级" value="priority" />
    </el-select>
    <el-button @click="store.resetFilters(); reload()">重置</el-button>
  </div>

  <el-table v-loading="store.loading" :data="store.items" @row-click="openDetail" class="case-table">
    <el-table-column prop="case_key" label="Case Key" width="150" />
    <el-table-column prop="title" label="标题" min-width="220" show-overflow-tooltip />
    <el-table-column label="状态" width="120">
      <template #default="{ row }"><StatusTag :status="row.status" /></template>
    </el-table-column>
    <el-table-column label="优先级" width="80">
      <template #default="{ row }"><PriorityTag :priority="row.priority" /></template>
    </el-table-column>
    <el-table-column prop="owner_team" label="团队" width="120" />
    <el-table-column prop="assignee" label="负责人" width="110" />
    <el-table-column label="SLA" width="140">
      <template #default="{ row }"><SlaBadge :due-at="row.due_at" :breached="row.sla_breached" /></template>
    </el-table-column>
    <el-table-column prop="version" label="版本" width="70" />
  </el-table>

  <el-pagination
    v-model:current-page="store.page"
    :page-size="store.pageSize"
    :total="store.total"
    layout="prev, pager, next, total"
    class="pager"
    @current-change="store.fetch()"
  />
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useCasesStore } from '../stores/cases'
import type { CaseDetail } from '../api/types'
import PriorityTag from '../components/PriorityTag.vue'
import StatusTag from '../components/StatusTag.vue'
import SlaBadge from '../components/SlaBadge.vue'

const store = useCasesStore()
const router = useRouter()

const STATUS_OPTIONS: Record<string, string> = {
  new: '新建',
  triage: '分诊',
  assigned: '已分派',
  in_progress: '整改中',
  awaiting_verification: '待复测',
  closed: '已关闭',
  risk_accepted: '风险已接受',
  not_applicable: '不适用',
  reopened: '已重开',
}

function reload() {
  store.page = 1
  store.fetch()
}

function openDetail(row: CaseDetail) {
  router.push(`/cases/${row.id}`)
}

onMounted(() => {
  store.fetch()
  timer = window.setInterval(() => {
    if (document.visibilityState === 'visible') store.fetch()
  }, 30_000)
})
let timer: number | undefined
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<style scoped>
.filters { display: flex; gap: 12px; align-items: center; margin-bottom: 14px; }
.case-table { cursor: pointer; }
.pager { margin-top: 14px; justify-content: flex-end; }
</style>
```

- [ ] **Step 5: Run tests, typecheck, and smoke**

```bash
cd frontend && pnpm test && pnpm typecheck && pnpm lint
```

Expected: PASS. Then with `uv run uvicorn ... --port 8000` running at repo root, `pnpm dev` → `/cases` shows real rows (create one via the README curl if DB is empty). Click a row → placeholder detail page.

- [ ] **Step 6: Commit**

```bash
git add frontend/src
git commit -m "feat(frontend): case list with filters and pagination"
```

---

### Task 4: Case detail view (read path)

**Files:**
- Create: `frontend/src/components/StatusStepper.vue`, `frontend/src/stores/caseDetail.ts`, `frontend/src/views/CaseDetailView.vue` (replace placeholder)
- Test: `frontend/src/components/StatusStepper.test.ts`, `frontend/src/stores/caseDetail.test.ts`

**Interfaces:**
- Consumes: `apiClient.getCase/listRiskDecisions/listVerifications`, `CaseDetail`, `RiskDecisionItem`, `VerificationItem`, shared tags (Task 3).
- Produces: `useCaseDetailStore` with state `{detail: CaseDetail | null, allowed: string[], decisions: RiskDecisionItem[], verifications: VerificationItem[], loading}` and actions `fetchAll(caseId: string)`, `refresh()`; `StatusStepper` (props `status: string`) mapping `new→0 … closed→5`, side states (`risk_accepted`/`not_applicable`/`reopened`) pinned to step 1 with an alert; route `/cases/:id` renders everything read-only.

- [ ] **Step 1: Write the failing tests**

`frontend/src/components/StatusStepper.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import StatusStepper from './StatusStepper.vue'

describe('StatusStepper', () => {
  it('marks triage as the active step (index 1)', () => {
    const w = mount(StatusStepper, { props: { status: 'triage' } })
    expect(w.findAll('.el-step')).toHaveLength(6)
    expect(w.findComponent({ name: 'ElSteps' }).props('active')).toBe(1)
  })

  it('pins side states to the triage step and shows an alert', () => {
    const w = mount(StatusStepper, { props: { status: 'risk_accepted' } })
    expect(w.find('.el-alert').text()).toContain('风险已接受')
  })
})
```

`frontend/src/stores/caseDetail.test.ts`:

```ts
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useCaseDetailStore } from './caseDetail'
import { useOrgStore } from './org'
import { apiClient } from '../api/client'

vi.mock('../api/client', () => ({
  apiClient: {
    getCase: vi.fn(),
    getAllowed: vi.fn(),
    listRiskDecisions: vi.fn(),
    listVerifications: vi.fn(),
  },
}))

describe('caseDetailStore', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('loads detail, allowed transitions, and histories together', async () => {
    const detail = { id: 'c1', status: 'triage', version: 2 }
    vi.mocked(apiClient.getCase).mockResolvedValue(detail as never)
    vi.mocked(apiClient.getAllowed).mockResolvedValue({ case_id: 'c1', status: 'triage', allowed: ['assigned', 'risk_accepted'], current: 'triage' })
    vi.mocked(apiClient.listRiskDecisions).mockResolvedValue({ items: [] })
    vi.mocked(apiClient.listVerifications).mockResolvedValue({ items: [] })

    const store = useCaseDetailStore()
    useOrgStore().setOrg('acme')
    await store.fetchAll('c1')

    expect(apiClient.getCase).toHaveBeenCalledWith('acme', 'c1')
    expect(store.detail).toEqual(detail)
    expect(store.allowed).toEqual(['assigned', 'risk_accepted'])
    expect(store.loading).toBe(false)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && pnpm test`
Expected: FAIL — StatusStepper/caseDetail missing.

- [ ] **Step 3: Implement StatusStepper + caseDetail store**

`frontend/src/components/StatusStepper.vue`:

```vue
<template>
  <div>
    <el-alert
      v-if="sideLabel"
      :title="`当前状态：${sideLabel}`"
      type="warning"
      show-icon
      :closable="false"
      class="side-alert"
    />
    <el-steps :active="active" align-center finish-status="success">
      <el-step v-for="s in STEPS" :key="s.value" :title="s.label" />
    </el-steps>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string }>()

const STEPS = [
  { value: 'new', label: '新建' },
  { value: 'triage', label: '分诊' },
  { value: 'assigned', label: '已分派' },
  { value: 'in_progress', label: '整改中' },
  { value: 'awaiting_verification', label: '待复测' },
  { value: 'closed', label: '已关闭' },
] as const

const SIDE_LABELS: Record<string, string> = {
  risk_accepted: '风险已接受',
  not_applicable: '不适用',
  reopened: '已重开（重新进入分诊）',
}

const active = computed(() => {
  const idx = STEPS.findIndex((s) => s.value === props.status)
  if (idx >= 0) return idx
  return 1 // side states branch off triage
})
const sideLabel = computed(() => SIDE_LABELS[props.status] ?? null)
</script>

<style scoped>
.side-alert { margin-bottom: 10px; }
</style>
```

`frontend/src/stores/caseDetail.ts`:

```ts
import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import type { CaseDetail, RiskDecisionItem, VerificationItem } from '../api/types'
import { useOrgStore } from './org'

export const useCaseDetailStore = defineStore('caseDetail', {
  state: () => ({
    detail: null as CaseDetail | null,
    allowed: [] as string[],
    decisions: [] as RiskDecisionItem[],
    verifications: [] as VerificationItem[],
    loading: false,
  }),
  actions: {
    async fetchAll(caseId: string) {
      this.loading = true
      try {
        const org = useOrgStore().org
        const [detail, allowed, decisions, verifications] = await Promise.all([
          apiClient.getCase(org, caseId),
          apiClient.getAllowed(org, caseId),
          apiClient.listRiskDecisions(org, caseId),
          apiClient.listVerifications(org, caseId),
        ])
        this.detail = detail
        this.allowed = allowed.allowed
        this.decisions = decisions.items
        this.verifications = verifications.items
      } finally {
        this.loading = false
      }
    },
    async refresh() {
      if (this.detail) await this.fetchAll(this.detail.id)
    },
  },
})
```

- [ ] **Step 4: Implement the detail view**

`frontend/src/views/CaseDetailView.vue`:

```vue
<template>
  <div v-if="store.detail" class="detail">
    <div class="detail-header">
      <el-page-header @back="router.back()">
        <template #content>
          <span class="case-key">{{ store.detail.case_key }}</span>
          <span class="case-title">{{ store.detail.title }}</span>
          <PriorityTag :priority="store.detail.priority" />
          <SlaBadge :due-at="store.detail.due_at" :breached="store.detail.sla_breached" />
        </template>
      </el-page-header>
    </div>

    <StatusStepper :status="store.detail.status" />

    <el-row :gutter="20" class="detail-body">
      <el-col :span="17">
        <el-tabs v-model="tab">
          <el-tab-pane label="暴露面" name="exposures">
            <el-empty v-if="!store.detail.exposures.length" description="无暴露面记录" />
            <el-table v-else :data="exposureRows">
              <el-table-column prop="id" label="Exposure ID" />
            </el-table>
          </el-tab-pane>
          <el-tab-pane :label="`风险决策 (${store.decisions.length})`" name="decisions">
            <el-empty v-if="!store.decisions.length" description="无风险决策" />
            <el-table v-else :data="store.decisions">
              <el-table-column prop="type" label="类型" width="140" />
              <el-table-column prop="status" label="状态" width="140" />
              <el-table-column prop="reason" label="原因" min-width="180" show-overflow-tooltip />
              <el-table-column prop="approver" label="审批人" width="110" />
              <el-table-column prop="expires_at" label="过期时间" width="180" />
              <el-table-column prop="created_at" label="创建时间" width="180" />
            </el-table>
          </el-tab-pane>
          <el-tab-pane :label="`复测记录 (${store.verifications.length})`" name="verifications">
            <el-empty v-if="!store.verifications.length" description="无复测记录" />
            <el-table v-else :data="store.verifications">
              <el-table-column prop="method" label="方式" width="150" />
              <el-table-column prop="status" label="结果" width="170" />
              <el-table-column prop="asserted_result" label="声称结果" width="120" />
              <el-table-column prop="created_at" label="时间" width="180" />
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </el-col>
      <el-col :span="7">
        <el-card header="元数据">
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="organization">{{ store.detail.organization_id }}</el-descriptions-item>
            <el-descriptions-item label="owner_team">{{ store.detail.owner_team }}</el-descriptions-item>
            <el-descriptions-item label="assignee">{{ store.detail.assignee ?? '—' }}</el-descriptions-item>
            <el-descriptions-item label="policy_version">{{ store.detail.policy_version ?? '—' }}</el-descriptions-item>
            <el-descriptions-item label="closure_reason">{{ store.detail.closure_reason ?? '—' }}</el-descriptions-item>
            <el-descriptions-item label="created_at">{{ store.detail.created_at }}</el-descriptions-item>
            <el-descriptions-item label="updated_at">{{ store.detail.updated_at }}</el-descriptions-item>
            <el-descriptions-item label="version">v{{ store.detail.version }}</el-descriptions-item>
          </el-descriptions>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useCaseDetailStore } from '../stores/caseDetail'
import StatusStepper from '../components/StatusStepper.vue'
import PriorityTag from '../components/PriorityTag.vue'
import SlaBadge from '../components/SlaBadge.vue'

const route = useRoute()
const router = useRouter()
const store = useCaseDetailStore()
const tab = ref('exposures')

const exposureRows = computed(() =>
  (store.detail?.exposures ?? []).map((id: string) => ({ id })),
)

let timer: number | undefined
onMounted(() => {
  store.fetchAll(route.params.id as string)
  timer = window.setInterval(() => {
    if (document.visibilityState === 'visible' && !store.loading) store.refresh()
  }, 15_000)
})
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<style scoped>
.detail-header { margin-bottom: 18px; }
.case-key { font-weight: 700; margin-right: 10px; }
.case-title { margin-right: 10px; }
.detail-body { margin-top: 22px; }
</style>
```

- [ ] **Step 5: Verify**

```bash
cd frontend && pnpm test && pnpm typecheck && pnpm lint
```

Expected: PASS. Dev-server smoke: from the list, click a case → detail renders stepper/tabs/metadata.

- [ ] **Step 6: Commit**

```bash
git add frontend/src
git commit -m "feat(frontend): case detail read view with histories"
```

---

### Task 5: Lifecycle actions — transitions, risk decision, verification, 412 flow

**Files:**
- Create: `frontend/src/components/CaseActionBar.vue`, `frontend/src/components/RiskDecisionDrawer.vue`, `frontend/src/components/VerificationDrawer.vue`
- Modify: `frontend/src/stores/caseDetail.ts` (add actions), `frontend/src/views/CaseDetailView.vue` (mount action bar + drawers)
- Test: `frontend/src/components/CaseActionBar.test.ts`, `frontend/src/stores/caseDetail.actions.test.ts`

**Interfaces:**
- Consumes: `apiClient.transition/createRiskDecision/submitVerification`, `ApiError`, `useCaseDetailStore` (Task 4).
- Produces: store actions `transition(target: string, actor: string, reason?: string)` (throws `ApiError` through), `decide(payload)`, `verify(payload)` — each refetches all data on success; `CaseActionBar` renders one button per allowed transition (label map below), opening drawers for `risk_accepted`/`not_applicable`; 412 triggers a confirm-refresh dialog.

- [ ] **Step 1: Write the failing tests**

`frontend/src/components/CaseActionBar.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import CaseActionBar from './CaseActionBar.vue'
import { useCaseDetailStore } from '../stores/caseDetail'

describe('CaseActionBar', () => {
  it('renders exactly one button per allowed transition', () => {
    setActivePinia(createPinia())
    const store = useCaseDetailStore()
    store.allowed = ['assigned', 'risk_accepted', 'not_applicable']
    const w = mount(CaseActionBar)
    const buttons = w.findAll('button.el-button').filter((b) => !b.attributes('disabled'))
    expect(buttons.map((b) => b.text())).toEqual(['流转到 已分派', '接受风险…', '标记不适用…'])
  })

  it('renders nothing when no transitions allowed', () => {
    setActivePinia(createPinia())
    useCaseDetailStore().allowed = []
    const w = mount(CaseActionBar)
    expect(w.findAll('button.el-button')).toHaveLength(0)
  })
})
```

`frontend/src/stores/caseDetail.actions.test.ts`:

```ts
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useCaseDetailStore } from './caseDetail'
import { useOrgStore } from './org'
import { apiClient } from '../api/client'

vi.mock('../api/client', () => ({
  apiClient: {
    getCase: vi.fn(),
    getAllowed: vi.fn(),
    listRiskDecisions: vi.fn(),
    listVerifications: vi.fn(),
    transition: vi.fn(),
    createRiskDecision: vi.fn(),
    submitVerification: vi.fn(),
  },
}))

function stubReads(detail = { id: 'c1', status: 'triage', version: 2 }) {
  vi.mocked(apiClient.getCase).mockResolvedValue(detail as never)
  vi.mocked(apiClient.getAllowed).mockResolvedValue({ case_id: 'c1', status: 'triage', allowed: [], current: 'triage' })
  vi.mocked(apiClient.listRiskDecisions).mockResolvedValue({ items: [] })
  vi.mocked(apiClient.listVerifications).mockResolvedValue({ items: [] })
}

describe('caseDetailStore actions', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    stubReads()
  })

  it('transitions with If-Match version and refetches', async () => {
    vi.mocked(apiClient.transition).mockResolvedValue({ id: 'c1', status: 'assigned', version: 3, etag: '"3"' })
    const store = useCaseDetailStore()
    useOrgStore().setOrg('acme')
    await store.fetchAll('c1')
    await store.transition('assigned', 'alice', 'ok')
    expect(apiClient.transition).toHaveBeenCalledWith('acme', 'c1', 2, 'assigned', 'alice', 'ok')
    expect(apiClient.getCase).toHaveBeenCalledTimes(2) // initial + refetch
  })

  it('submits a risk decision payload with approver fields', async () => {
    vi.mocked(apiClient.createRiskDecision).mockResolvedValue({ id: 'rd1' } as never)
    const store = useCaseDetailStore()
    useOrgStore().setOrg('acme')
    await store.fetchAll('c1')
    await store.decide({ type: 'risk_accepted', reason: 'waf', evidence_ids: ['e1'], requested_by: 'a', approver: 'b', approver_role: 'security_lead' })
    expect(apiClient.createRiskDecision).toHaveBeenCalledWith('acme', 'c1', expect.objectContaining({ type: 'risk_accepted' }))
  })

  it('submits verification payload', async () => {
    vi.mocked(apiClient.submitVerification).mockResolvedValue({ id: 'v1', status: 'closed' } as never)
    const store = useCaseDetailStore()
    useOrgStore().setOrg('acme')
    await store.fetchAll('c1')
    await store.verify({ method: 'scanner', coverage: { status: 'complete', scope_version: 'v2' }, evidence_ids: [] })
    expect(apiClient.submitVerification).toHaveBeenCalledWith('acme', 'c1', expect.objectContaining({ method: 'scanner' }))
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && pnpm test`
Expected: FAIL — store actions and CaseActionBar missing.

- [ ] **Step 3: Add store actions**

Append to the `actions` object in `frontend/src/stores/caseDetail.ts`:

```ts
    async transition(target: string, actor: string, reason?: string) {
      const org = useOrgStore().org
      const detail = this.detail
      if (!detail) return
      await apiClient.transition(org, detail.id, detail.version, target, actor, reason)
      await this.fetchAll(detail.id)
    },
    async decide(payload: Record<string, unknown>) {
      const org = useOrgStore().org
      if (!this.detail) return
      await apiClient.createRiskDecision(org, this.detail.id, payload)
      await this.fetchAll(this.detail.id)
    },
    async verify(payload: Record<string, unknown>) {
      const org = useOrgStore().org
      if (!this.detail) return
      await apiClient.submitVerification(org, this.detail.id, payload)
      await this.fetchAll(this.detail.id)
    },
```

- [ ] **Step 4: Implement the action bar**

`frontend/src/components/CaseActionBar.vue`:

```vue
<template>
  <div class="action-bar">
    <template v-for="target in store.allowed" :key="target">
      <el-button v-if="target === 'risk_accepted'" type="warning" plain @click="riskVisible = true">
        接受风险…
      </el-button>
      <el-button v-else-if="target === 'not_applicable'" type="info" plain @click="riskMode = 'not_applicable'; riskVisible = true">
        标记不适用…
      </el-button>
      <el-button v-else type="primary" plain :data-test="`transition-${target}`" @click="doTransition(target)">
        流转到 {{ TARGET_LABELS[target] ?? target }}
      </el-button>
    </template>

    <RiskDecisionDrawer v-model="riskVisible" :mode="riskMode" />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'
import { ApiError } from '../api/client'
import RiskDecisionDrawer from './RiskDecisionDrawer.vue'

const store = useCaseDetailStore()
const riskVisible = ref(false)
const riskMode = ref<'risk_accepted' | 'not_applicable'>('risk_accepted')

const TARGET_LABELS: Record<string, string> = {
  triage: '分诊',
  assigned: '已分派',
  in_progress: '整改中',
  awaiting_verification: '待复测',
  closed: '已关闭',
  reopened: '重开',
}

async function doTransition(target: string) {
  try {
    await store.transition(target, 'console-user')
    ElMessage.success(`已流转到 ${TARGET_LABELS[target] ?? target}`)
  } catch (err) {
    if (err instanceof ApiError && err.status === 412) {
      await ElMessageBox.confirm('工单已被他人修改。刷新后重试？', '版本冲突', {
        confirmButtonText: '刷新',
        cancelButtonText: '取消',
        type: 'warning',
      })
      await store.refresh()
      return
    }
    ElMessage.error(err instanceof Error ? err.message : '流转失败')
  }
}
</script>

<style scoped>
.action-bar { margin: 16px 0; display: flex; gap: 8px; }
</style>
```

- [ ] **Step 5: Implement the risk decision drawer**

`frontend/src/components/RiskDecisionDrawer.vue`:

```vue
<template>
  <el-drawer v-model="visible" :title="title" size="420px">
    <el-form label-width="90px">
      <el-form-item label="类型">
        <el-select v-model="form.type" :disabled="mode === 'not_applicable'">
          <el-option label="风险接受" value="risk_accepted" />
          <el-option label="误报" value="false_positive" />
          <el-option label="不受影响" value="not_affected" />
        </el-select>
      </el-form-item>
      <el-form-item label="原因" required>
        <el-input v-model="form.reason" type="textarea" :rows="3" />
      </el-form-item>
      <el-form-item label="证据 ID">
        <el-input v-model="evidenceText" placeholder="逗号分隔，如 ev-1,ev-2" />
      </el-form-item>
      <el-form-item label="申请人">
        <el-input v-model="form.requested_by" />
      </el-form-item>
      <el-form-item label="审批人" required>
        <el-input v-model="form.approver" />
      </el-form-item>
      <el-form-item label="审批角色" required>
        <el-select v-model="form.approver_role">
          <el-option label="风险审批人" value="risk_approver" />
          <el-option label="安全负责人" value="security_lead" />
          <el-option label="策略管理员" value="policy_admin" />
        </el-select>
      </el-form-item>
      <el-form-item label="失效时间">
        <el-date-picker v-model="form.expires_at" type="datetime" value-format="YYYY-MM-DDTHH:mm:ssZ" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="submitting" @click="submit">提交决策</el-button>
      </el-form-item>
    </el-form>
  </el-drawer>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'

const props = defineProps<{ mode: 'risk_accepted' | 'not_applicable' }>()
const visible = defineModel<boolean>({ default: false })

const store = useCaseDetailStore()
const submitting = ref(false)

const title = computed(() => (props.mode === 'not_applicable' ? '标记不适用' : '风险接受申请'))

const form = reactive({
  type: 'risk_accepted',
  reason: '',
  requested_by: '',
  approver: '',
  approver_role: 'security_lead',
  expires_at: '',
})
const evidenceText = ref('')

watch(visible, (v) => {
  if (v && props.mode === 'not_applicable') form.type = 'not_affected'
  if (v && props.mode === 'risk_accepted') form.type = 'risk_accepted'
})

async function submit() {
  if (!form.reason.trim() || !form.approver.trim() || !form.approver_role) {
    ElMessage.warning('原因、审批人与审批角色为必填（否则只会进入待审批状态）')
    return
  }
  submitting.value = true
  try {
    await store.decide({
      type: form.type,
      reason: form.reason,
      evidence_ids: evidenceText.value.split(',').map((s) => s.trim()).filter(Boolean),
      requested_by: form.requested_by || 'console-user',
      approver: form.approver,
      approver_role: form.approver_role,
      expires_at: form.expires_at || undefined,
    })
    ElMessage.success('决策已提交')
    visible.value = false
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '提交失败')
  } finally {
    submitting.value = false
  }
}
</script>
```

- [ ] **Step 6: Implement the verification drawer and wire everything into the detail view**

`frontend/src/components/VerificationDrawer.vue`:

```vue
<template>
  <el-drawer v-model="visible" title="提交复测证据" size="420px">
    <el-form label-width="110px">
      <el-form-item label="复测方式">
        <el-select v-model="form.method">
          <el-option label="扫描器复测" value="scanner" />
          <el-option label="Wazuh 主机清单" value="wazuh_inventory" />
          <el-option label="人工确认" value="manual_attestation" />
        </el-select>
      </el-form-item>
      <el-form-item label="覆盖结果">
        <el-select v-model="form.coverage.status">
          <el-option label="完整 (complete)" value="complete" />
          <el-option label="部分 (partial)" value="partial" />
          <el-option label="失败 (failed)" value="failed" />
        </el-select>
      </el-form-item>
      <el-form-item v-if="form.method === 'scanner'" label="范围版本">
        <el-input v-model="form.coverage.scope_version" placeholder="如 v2（复测扫描的范围标识）" />
      </el-form-item>
      <el-form-item label="证据 ID">
        <el-input v-model="evidenceText" placeholder="逗号分隔" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="submitting" @click="submit">提交复测</el-button>
      </el-form-item>
      <el-alert
        title="partial / failed / 过期证据永远不会关闭工单（never close on missing data）"
        type="info"
        :closable="false"
      />
    </el-form>
  </el-drawer>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'

const visible = defineModel<boolean>({ default: false })
const store = useCaseDetailStore()
const submitting = ref(false)
const evidenceText = ref('')

const form = reactive({
  method: 'scanner',
  coverage: { status: 'complete', scope_version: '' },
})

async function submit() {
  submitting.value = true
  try {
    const coverage: Record<string, unknown> = { status: form.coverage.status }
    if (form.method === 'scanner' && form.coverage.scope_version) {
      coverage.scope_version = form.coverage.scope_version
    }
    await store.verify({
      method: form.method,
      coverage,
      evidence_ids: evidenceText.value.split(',').map((s) => s.trim()).filter(Boolean),
    })
    ElMessage.success('复测证据已提交')
    visible.value = false
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '提交失败')
  } finally {
    submitting.value = false
  }
}
</script>
```

Modify `frontend/src/views/CaseDetailView.vue`:

1. Import the three new components and add `verifyVisible` state:

```ts
import CaseActionBar from '../components/CaseActionBar.vue'
import RiskDecisionDrawer from '../components/RiskDecisionDrawer.vue'
import VerificationDrawer from '../components/VerificationDrawer.vue'

const verifyVisible = ref(false)
```

2. In the template, insert the action bar right below `<StatusStepper … />`, and the verification drawer at the bottom of the root div:

```html
    <CaseActionBar @transition-done="() => {}" />
```

and inside `CaseActionBar.vue` add the verification entry — append after the template's last `el-button` (inside the root div):

```html
    <el-button
      v-if="store.detail?.status === 'awaiting_verification'"
      type="success"
      plain
      @click="$emit('verify')"
    >
      提交复测证据…
    </el-button>
```

with `defineEmits<{ verify: [] }>()` added next to the existing `defineProps`-free script setup, and in `CaseDetailView.vue` change the mount to:

```html
    <CaseActionBar @verify="verifyVisible = true" />
    <VerificationDrawer v-model="verifyVisible" />
```

(Note: `RiskDecisionDrawer` is mounted by `CaseActionBar` itself; `VerificationDrawer` is mounted by the detail view because the verify button lives in the action bar but needs the view-level drawer.)

- [ ] **Step 7: Verify**

```bash
cd frontend && pnpm test && pnpm typecheck && pnpm lint
```

Expected: PASS. Dev-server smoke: on a case in `new`, click 流转到 分诊 → status tag updates, version increments; try the same in two tabs to see the 412 dialog.

- [ ] **Step 8: Commit**

```bash
git add frontend/src
git commit -m "feat(frontend): case lifecycle actions with optimistic locking"
```

---

### Task 6: Dashboard (stat cards + charts)

**Files:**
- Create: `frontend/src/stores/dashboard.ts`, `frontend/src/components/BaseChart.vue`, `frontend/src/views/DashboardView.vue` (replace placeholder)
- Test: `frontend/src/stores/dashboard.test.ts`

**Interfaces:**
- Consumes: `apiClient.listCases` (count-only queries use `page_size=1` and read `total`), `useOrgStore`, shared tags.
- Produces: `useDashboardStore` with state `{byPriority: Record<string, number>, breached: number, openCount: number, p0p1Open: number, avgCloseDays: number | null, slaTrend: Array<{date: string, rate: number}>, loading}` and action `fetch()`; `BaseChart` (props `option: EChartsOption`, wraps echarts init/resize/dispose); dashboard route shows cards + pie + SLA trend line.

- [ ] **Step 1: Write the failing test**

`frontend/src/stores/dashboard.test.ts`:

```ts
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useDashboardStore } from './dashboard'
import { useOrgStore } from './org'
import { apiClient } from '../api/client'

vi.mock('../api/client', () => ({ apiClient: { listCases: vi.fn() } }))

function totalFor(query: string): number {
  const params = new URLSearchParams(query)
  const status = params.get('status') ?? ''
  const priority = params.get('priority') ?? ''
  if (params.get('sla_breached') === 'true') return 3
  if (priority === 'P0') return 0
  if (priority === 'P1') {
    if (status === 'closed') return 2
    if (status === 'risk_accepted') return 1
    if (status === 'not_applicable') return 0
    return 7
  }
  if (priority === 'P2') return 5
  if (status === 'closed') return 4
  if (status === 'risk_accepted') return 1
  if (status === 'not_applicable') return 2
  return 20
}

describe('dashboardStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    const recentClosed = [
      { status: 'closed', created_at: '2026-09-01T00:00:00+00:00', updated_at: '2026-09-02T00:00:00+00:00', due_at: '2026-09-04T00:00:00+00:00' },
      { status: 'closed', created_at: '2026-09-01T00:00:00+00:00', updated_at: '2026-09-04T00:00:00+00:00', due_at: '2026-09-03T00:00:00+00:00' },
    ]
    vi.mocked(apiClient.listCases).mockImplementation(async (_org, query = '') =>
      query.includes('page_size=100')
        ? { items: recentClosed as never, total: recentClosed.length, page: 1, page_size: 100 }
        : { items: [], total: totalFor(query), page: 1, page_size: 1 },
    )
  })

  it('computes counts, P0/P1 open, SLA trend, and average close time', async () => {
    useOrgStore().setOrg('acme')
    const store = useDashboardStore()
    await store.fetch()
    expect(store.byPriority).toEqual({ P0: 0, P1: 7, P2: 5, P3: 0, P4: 0 })
    expect(store.breached).toBe(3)
    expect(store.openCount).toBe(20 - 4 - 1 - 2)
    // P1 open = 7 − 2 closed − 1 risk_accepted − 0 not_applicable; P0 open = 0
    expect(store.p0p1Open).toBe(4)
    // item1 closes in 1 day (on time), item2 in 3 days (late) → avg 2.0
    expect(store.avgCloseDays).toBe(2)
    // one trend point per close day: 09-02 on time, 09-04 late
    expect(store.slaTrend).toEqual([
      { date: '2026-09-02', rate: 100 },
      { date: '2026-09-04', rate: 0 },
    ])
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && pnpm test`
Expected: FAIL — dashboard store missing.

- [ ] **Step 3: Implement dashboard store**

`frontend/src/stores/dashboard.ts`:

```ts
import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import { useOrgStore } from './org'

export const useDashboardStore = defineStore('dashboard', {
  state: () => ({
    byPriority: { P0: 0, P1: 0, P2: 0, P3: 0, P4: 0 } as Record<string, number>,
    breached: 0,
    openCount: 0,
    p0p1Open: 0,
    avgCloseDays: null as number | null,
    slaTrend: [] as Array<{ date: string; rate: number }>,
    loading: false,
  }),
  actions: {
    async fetch() {
      this.loading = true
      try {
        const org = useOrgStore().org
        const count = async (query: string) =>
          (await apiClient.listCases(org, `?page_size=1&${query}`)).total

        const priorities = ['P0', 'P1', 'P2', 'P3', 'P4'] as const
        const counts = await Promise.all(priorities.map((p) => count(`priority=${p}`)))
        priorities.forEach((p, i) => {
          this.byPriority[p] = counts[i]
        })

        const [all, closed, riskAccepted, notApplicable] = await Promise.all([
          count(''),
          count('status=closed'),
          count('status=risk_accepted'),
          count('status=not_applicable'),
        ])
        this.openCount = all - closed - riskAccepted - notApplicable
        this.breached = await count('sla_breached=true')

        // P0/P1 未关闭 = 各自总数 − 已关闭 − 风险接受 − 不适用
        const highPriOpen = async (p: string) => {
          const [total, c, r, n] = await Promise.all([
            count(`priority=${p}`),
            count(`priority=${p}&status=closed`),
            count(`priority=${p}&status=risk_accepted`),
            count(`priority=${p}&status=not_applicable`),
          ])
          return total - c - r - n
        }
        const [p0, p1] = await Promise.all([highPriOpen('P0'), highPriOpen('P1')])
        this.p0p1Open = p0 + p1

        // 平均关闭时长：从最近 100 条已关闭工单估算（spec §5.2 的 MVP 简化）
        const recent = await apiClient.listCases(org, '?page_size=100&status=closed&sort=-updated_at')
        const durations = recent.items
          .filter((c) => c.created_at && c.updated_at)
          .map((c) => (new Date(c.updated_at!).getTime() - new Date(c.created_at!).getTime()) / 86_400_000)
        this.avgCloseDays =
          durations.length > 0
            ? Math.round((durations.reduce((a, b) => a + b, 0) / durations.length) * 10) / 10
            : null

        // SLA 达成率趋势：按关闭日分桶，on-time = updated_at <= due_at
        const trend = new Map<string, { onTime: number; total: number }>()
        for (const c of recent.items) {
          if (!c.updated_at || !c.due_at) continue
          const day = c.updated_at.slice(0, 10)
          const bucket = trend.get(day) ?? { onTime: 0, total: 0 }
          bucket.total += 1
          if (new Date(c.updated_at).getTime() <= new Date(c.due_at).getTime()) bucket.onTime += 1
          trend.set(day, bucket)
        }
        this.slaTrend = [...trend.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([date, b]) => ({ date, rate: Math.round((b.onTime / b.total) * 100) }))
      } finally {
        this.loading = false
      }
    },
  },
})
```

- [ ] **Step 4: Implement BaseChart + dashboard view**

`frontend/src/components/BaseChart.vue`:

```vue
<template>
  <div ref="el" class="base-chart" :style="{ height }" />
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import type { EChartsOption } from 'echarts'

const props = defineProps<{ option: EChartsOption; height?: string }>()
const el = ref<HTMLDivElement>()
let chart: echarts.ECharts | null = null

onMounted(() => {
  chart = echarts.init(el.value!)
  chart.setOption(props.option)
  window.addEventListener('resize', resize)
})
watch(
  () => props.option,
  (option) => chart?.setOption(option, true),
  { deep: true },
)
function resize() {
  chart?.resize()
}
onBeforeUnmount(() => {
  window.removeEventListener('resize', resize)
  chart?.dispose()
})
</script>

<style scoped>
.base-chart { width: 100%; }
</style>
```

(`height` prop defaults to `undefined`; pass e.g. `height="320px"` at usage sites. The `:style` binding yields `height: undefined` → falls back to the div's content height; always pass an explicit height.)

`frontend/src/views/DashboardView.vue`:

```vue
<template>
  <el-row v-loading="store.loading" :gutter="16">
    <el-col :span="6"><el-card><el-statistic title="未关闭工单" :value="store.openCount" /></el-card></el-col>
    <el-col :span="6">
      <el-card><el-statistic title="SLA 已超时" :value="store.breached" :value-style="{ color: '#f56c6c' }" /></el-card>
    </el-col>
    <el-col :span="6"><el-card><el-statistic title="P0·P1 未关闭" :value="store.p0p1Open" /></el-card></el-col>
    <el-col :span="6">
      <el-card>
        <el-statistic
          title="平均关闭时长（近100条）"
          :value="store.avgCloseDays ?? 0"
          :precision="1"
          suffix=" 天"
        />
      </el-card>
    </el-col>
  </el-row>

  <el-row :gutter="16" class="charts">
    <el-col :span="12">
      <el-card header="优先级分布">
        <BaseChart :option="pieOption" height="320px" />
      </el-card>
    </el-col>
    <el-col :span="12">
      <el-card header="SLA 达成趋势（按天，近100条已关闭）">
        <BaseChart :option="trendOption" height="320px" />
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard'
import BaseChart from '../components/BaseChart.vue'

const store = useDashboardStore()

const pieOption = computed(() => ({
  tooltip: {},
  series: [
    {
      type: 'pie',
      radius: ['40%', '70%'],
      data: Object.entries(store.byPriority).map(([name, value]) => ({ name, value })),
    },
  ],
}))

const trendOption = computed(() => ({
  tooltip: { formatter: '{b}: {c}%' },
  xAxis: { type: 'category', data: store.slaTrend.map((p) => p.date) },
  yAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } },
  series: [{ type: 'line', data: store.slaTrend.map((p) => p.rate), areaStyle: {} }],
}))

onMounted(() => {
  store.fetch()
  timer = window.setInterval(() => {
    if (document.visibilityState === 'visible') store.fetch()
  }, 30_000)
})
let timer: number | undefined
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<style scoped>
.charts { margin-top: 16px; }
</style>
```

- [ ] **Step 5: Verify**

```bash
cd frontend && pnpm test && pnpm typecheck && pnpm lint
```

Expected: PASS. Dev smoke: `/` shows cards with real counts and two charts (values match the list page's total).

- [ ] **Step 6: Commit**

```bash
git add frontend/src
git commit -m "feat(frontend): dashboard with stat cards and charts"
```

---

### Task 7: SBOM submit page

**Files:**
- Create: `frontend/src/views/SbomSubmitView.vue` (replace placeholder)
- Test: `frontend/src/views/SbomSubmit.test.ts`

**Interfaces:**
- Consumes: `apiClient.submitSbom`, `ApiError`, `useOrgStore`.
- Produces: `/sboms` route page: paste/upload CycloneDX or SPDX JSON → shows `sbom_id`/`content_sha256`/idempotent status; keeps submission history in `localStorage` key `vulnops.sbom-history`.

- [ ] **Step 1: Write the failing test**

`frontend/src/views/SbomSubmit.test.ts`:

```ts
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import SbomSubmitView from './SbomSubmitView.vue'
import { useOrgStore } from '../stores/org'
import { apiClient } from '../api/client'

vi.mock('../api/client', () => ({ apiClient: { submitSbom: vi.fn() } }))

describe('SbomSubmitView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.mocked(apiClient.submitSbom).mockReset()
  })

  it('submits parsed JSON with an idempotency key and records history', async () => {
    vi.mocked(apiClient.submitSbom).mockResolvedValue({
      sbom_id: 'sbom_1', content_sha256: 'abc', status: 'accepted',
    })
    useOrgStore().setOrg('acme')
    const w = mount(SbomSubmitView)
    await w.find('textarea').setValue('{"bomFormat":"CycloneDX","specVersion":"1.5"}')
    await w.find('button.submit-btn').trigger('click')
    expect(apiClient.submitSbom).toHaveBeenCalledWith(
      'acme',
      { bomFormat: 'CycloneDX', specVersion: '1.5' },
      expect.any(String),
    )
    const history = JSON.parse(localStorage.getItem('vulnops.sbom-history')!)
    expect(history).toHaveLength(1)
    expect(history[0].sbom_id).toBe('sbom_1')
  })

  it('shows an error for invalid JSON without calling the API', async () => {
    const w = mount(SbomSubmitView)
    await w.find('textarea').setValue('not json')
    await w.find('button.submit-btn').trigger('click')
    expect(apiClient.submitSbom).not.toHaveBeenCalled()
    expect(w.text()).toContain('不是合法的 JSON')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && pnpm test`
Expected: FAIL — SbomSubmitView is still the placeholder.

- [ ] **Step 3: Implement the view**

`frontend/src/views/SbomSubmitView.vue`:

```vue
<template>
  <el-card header="提交 SBOM（CycloneDX / SPDX）">
    <el-input
      v-model="text"
      type="textarea"
      :rows="12"
      placeholder='粘贴 CycloneDX 或 SPDX JSON，例如 {"bomFormat":"CycloneDX","specVersion":"1.5","components":[…]}'
    />
    <div class="actions">
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="onFile">
        <el-button>从文件读取</el-button>
      </el-upload>
      <el-button type="primary" class="submit-btn" :loading="submitting" @click="submit">提交</el-button>
    </div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" class="result" />
    <el-descriptions v-if="result" :column="1" border class="result" title="摄取结果">
      <el-descriptions-item label="sbom_id">{{ result.sbom_id }}</el-descriptions-item>
      <el-descriptions-item label="content_sha256">{{ result.content_sha256 }}</el-descriptions-item>
      <el-descriptions-item label="status">{{ result.status }}</el-descriptions-item>
    </el-descriptions>
  </el-card>

  <el-card header="本地提交历史" class="history">
    <el-table :data="history" size="small">
      <el-table-column prop="at" label="时间" width="200" />
      <el-table-column prop="org" label="组织" width="140" />
      <el-table-column prop="sbom_id" label="SBOM ID" />
      <el-table-column prop="sha" label="SHA-256" show-overflow-tooltip />
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import type { UploadFile } from 'element-plus'
import { apiClient, ApiError } from '../api/client'
import { useOrgStore } from '../stores/org'

const HISTORY_KEY = 'vulnops.sbom-history'

const text = ref('')
const submitting = ref(false)
const error = ref('')
const result = ref<Record<string, string> | null>(null)
const history = ref<Array<{ at: string; org: string; sbom_id: string; sha: string }>>([])

function loadHistory() {
  history.value = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]')
}

function onFile(file: UploadFile) {
  file.raw?.text().then((t) => (text.value = t))
}

async function submit() {
  error.value = ''
  result.value = null
  let payload: unknown
  try {
    payload = JSON.parse(text.value)
  } catch {
    error.value = '输入不是合法的 JSON'
    return
  }
  submitting.value = true
  try {
    const key = crypto.randomUUID()
    const resp = await apiClient.submitSbom(useOrgStore().org, payload, key)
    result.value = {
      sbom_id: String(resp.sbom_id ?? ''),
      content_sha256: String(resp.content_sha256 ?? ''),
      status: String(resp.status ?? ''),
    }
    history.value = [
      {
        at: new Date().toLocaleString(),
        org: useOrgStore().org,
        sbom_id: result.value.sbom_id,
        sha: result.value.content_sha256,
      },
      ...history.value,
    ].slice(0, 20)
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.value))
    ElMessage.success('SBOM 已接受')
  } catch (err) {
    error.value = err instanceof ApiError ? `后端拒绝（${err.status}）：${err.message}` : '提交失败'
  } finally {
    submitting.value = false
  }
}

onMounted(loadHistory)
</script>

<style scoped>
.actions { margin-top: 12px; display: flex; gap: 12px; }
.result { margin-top: 16px; }
.history { margin-top: 16px; }
</style>
```

- [ ] **Step 4: Verify and commit**

```bash
cd frontend && pnpm test && pnpm typecheck && pnpm lint
git add frontend/src
git commit -m "feat(frontend): SBOM submit page with local history"
```

---

### Task 8: FastAPI static hosting + Dockerfile

**Files:**
- Create: `src/vulnops/api/frontend.py`
- Modify: `src/vulnops/main.py` (mount frontend + root serves index)
- Modify: `Dockerfile` (multi-stage)
- Test: `tests/api/test_frontend_serving.py`

**Interfaces:**
- Consumes: `frontend/dist` produced by Task 1's build.
- Produces: `mount_frontend(app)` called last in `create_app()`; GET `/` and unknown paths serve `index.html` when dist exists, unchanged JSON/404 behavior when it doesn't; Docker image contains the built SPA.

- [ ] **Step 1: Write the failing test**

`tests/api/test_frontend_serving.py`:

```python
from fastapi.testclient import TestClient

from vulnops.main import create_app


def test_root_returns_json_when_no_dist(monkeypatch):
    monkeypatch.setattr("vulnops.api.frontend.DIST", None, raising=False)
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "vulnops-hub"


def test_unknown_html_path_gets_404_json_when_no_dist(monkeypatch):
    monkeypatch.setattr("vulnops.api.frontend.DIST", None, raising=False)
    client = TestClient(create_app())
    resp = client.get("/some/spa/route")
    assert resp.status_code == 404
```

(`vulnops.api.frontend.DIST` is patched to `None` so the tests pass in CI where no dist exists; `mount_frontend` must treat `DIST is None` and "dist missing" identically.)

- [ ] **Step 2: Run tests to verify they fail meaningfully**

Run: `uv run pytest tests/api/test_frontend_serving.py -v`
Expected: PASS already for 404 (current behavior) but the `monkeypatch.setattr` fails with AttributeError since the module doesn't exist — that's the failing state to fix.

- [ ] **Step 3: Implement `frontend.py` and wire into `main.py`**

`src/vulnops/api/frontend.py`:

```python
from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# src/vulnops/api/frontend.py -> parents[3] is the repo root (or /app in Docker)
DIST: Path | None = Path(__file__).resolve().parents[3] / "frontend" / "dist"


def _dist_dir() -> Path | None:
    if DIST is not None and (DIST / "index.html").is_file():
        return DIST
    return None


def frontend_index_response() -> FileResponse | None:
    dist = _dist_dir()
    if dist is None:
        return None
    return FileResponse(dist / "index.html")


def mount_frontend(app) -> None:
    """Serve the built SPA. Must be called AFTER all API routers are registered."""
    dist = _dist_dir()
    if dist is None:
        return
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        if full_path.startswith(("api/", "health", "docs", "openapi.json")):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = (dist / full_path).resolve()
        if candidate.is_file() and str(candidate).startswith(str(dist)):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
```

In `src/vulnops/main.py`:

1. Change the root route (lines 82-89) to serve the SPA when built:

```python
    from vulnops.api.frontend import frontend_index_response

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        index = frontend_index_response()
        if index is not None:
            return index
        return {
            "service": settings.app_name,
            "version": settings.app_version or __version__,
            "docs": "/docs",
            "health": "/health/live",
        }
```

2. Add the mount as the last statement of `create_app()` (after the root route, before `return app`):

```python
    from vulnops.api.frontend import mount_frontend

    mount_frontend(app)
    return app
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/api/test_frontend_serving.py tests/api -v`
Expected: PASS — API tests unaffected (no dist in the test environment, `mount_frontend` no-ops).

- [ ] **Step 5: Manual verification with a real dist**

```bash
cd frontend && pnpm build && cd ..
uv run uvicorn vulnops.main:app --port 8000
curl -s -o /dev/null -w "%{http_code} %{content_type}\n" http://127.0.0.1:8000/
curl -s -o /dev/null -w "%{http_code} %{content_type}\n" http://127.0.0.1:8000/cases
curl -s http://127.0.0.1:8000/health/live | head -c 80; echo
```

Expected: both HTML requests return `200 text/html`; health stays JSON.

- [ ] **Step 6: Multi-stage Dockerfile**

Replace `Dockerfile` contents:

```dockerfile
FROM node:22-alpine AS frontend
WORKDIR /app
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml /app/
RUN pnpm install --frozen-lockfile
COPY frontend/ /app/
RUN pnpm build

FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY --from=frontend /app/dist ./frontend/dist

RUN pip install --upgrade pip && pip install -e . && pip install uvicorn[standard]

EXPOSE 8000
CMD ["uvicorn", "vulnops.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Commit:

```bash
uv run ruff check src tests
git add src/vulnops/api/frontend.py src/vulnops/main.py Dockerfile tests/api/test_frontend_serving.py
git commit -m "feat: serve SPA from FastAPI with SPA fallback, multi-stage Docker build"
```

---

### Task 9: Playwright smoke + CI job + README

**Files:**
- Create: `frontend/playwright.config.ts`, `frontend/e2e/cases.spec.ts`
- Modify: `.github/workflows/ci.yml` (frontend job), `README.md` (frontend section)

**Interfaces:**
- Consumes: running app (backend :8010 + built SPA :4173 with `VITE_API_TARGET`), `data-test` attributes from Task 5 (`transition-triage`).
- Produces: `pnpm e2e` green locally; CI `frontend` job (lint/typecheck/test/build) + optional `e2e` job.

- [ ] **Step 1: Playwright config + smoke spec**

`frontend/playwright.config.ts`:

```ts
import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  use: { baseURL: 'http://127.0.0.1:4173' },
  webServer: [
    {
      command: 'rm -f /tmp/vulnops-e2e.db && uv run uvicorn vulnops.main:app --port 8010',
      url: 'http://127.0.0.1:8010/health/live',
      reuseExistingServer: false,
      cwd: '..',
      env: { DATABASE_URL: 'sqlite:////tmp/vulnops-e2e.db' },
    },
    {
      command: 'pnpm preview --port 4173 --strictPort',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: false,
      env: { VITE_API_TARGET: 'http://127.0.0.1:8010' },
    },
  ],
})
```

`frontend/e2e/cases.spec.ts`:

```ts
import { expect, test } from '@playwright/test'

const ORG = 'e2e-org'

test('create a case via API, see it in list, walk it to triage', async ({ page, request }) => {
  const created = await request.post(`http://127.0.0.1:8010/api/v1/organizations/${ORG}/cases`, {
    data: { title: 'E2E case', owner_team: 'platform', priority: 'P2' },
  })
  expect(created.ok()).toBeTruthy()
  const { id } = await created.json()

  await page.goto('/cases')
  await expect(page.getByText('E2E case')).toBeVisible()

  await page.getByText('E2E case').click()
  await expect(page.getByText(id)).toBeVisible()

  await page.getByTestId('transition-triage').click()
  await expect(page.getByText('分诊')).toBeVisible()
  await expect(page.getByText('v2')).toBeVisible()
})
```

- [ ] **Step 2: Run e2e**

```bash
cd frontend && pnpm build && pnpm exec playwright install chromium && pnpm exec playwright test
```

Expected: 1 passed (backend spins on :8010 with a disposable DB, preview on :4173).

- [ ] **Step 3: Add CI jobs**

Append to `.github/workflows/ci.yml` jobs (same indentation as existing jobs):

```yaml
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: pnpm
          cache-dependency-path: frontend/pnpm-lock.yaml
      - name: Install
        run: pnpm install --frozen-lockfile
        working-directory: frontend
      - name: Lint
        run: pnpm lint
        working-directory: frontend
      - name: Type check
        run: pnpm typecheck
        working-directory: frontend
      - name: Unit tests
        run: pnpm test
        working-directory: frontend
      - name: Build
        run: pnpm build
        working-directory: frontend

  e2e:
    runs-on: ubuntu-latest
    needs: [lint-type-test, frontend]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install uv && uv sync --extra dev
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: pnpm
          cache-dependency-path: frontend/pnpm-lock.yaml
      - run: pnpm install --frozen-lockfile
        working-directory: frontend
      - run: pnpm build
        working-directory: frontend
      - run: pnpm exec playwright install --with-deps chromium
        working-directory: frontend
      - name: E2E smoke
        run: pnpm exec playwright test
        working-directory: frontend
```

- [ ] **Step 4: Update README**

In the README's `## Quick start` intro sentence, replace "no external services are needed for local evaluation — the API falls back to a SQLite file (`vulnops.db`)." with:

```markdown
No external services are needed for local evaluation — the API falls back to a
SQLite file (`vulnops.db`). A web console is available: run `make
frontend-install` once, then `make frontend-dev` in a second terminal and open
`http://localhost:5173` (the Vite dev server proxies `/api` to `:8000`).
```

Replace the status blockquote's "no web frontend yet; the API and its Swagger UI are the interface." sentence with:

```markdown
> A Vue 3 ops console ships in `frontend/` (dashboard, case lifecycle, SBOM
> submission). OIDC is not enforced yet — deploy only behind your intranet.
```

And in "## Repository status and contribution", replace the "There is no web frontend yet — the REST API and its Swagger UI at `/docs` are the interface." sentence with:

```markdown
The web console (`frontend/`, Vue 3 + Element Plus) covers the remediation
workflow: dashboard, case list/detail with state-machine actions, risk
decisions, verification, and SBOM submission.
```

- [ ] **Step 5: Full verification and commit**

```bash
cd frontend && pnpm test && pnpm lint && pnpm typecheck && pnpm build && pnpm exec playwright test
cd .. && uv run pytest -q && uv run ruff check src tests
git add .github/workflows/ci.yml frontend/playwright.config.ts frontend/e2e README.md
git commit -m "feat(frontend): e2e smoke, CI jobs, README console docs"
```

Expected: everything green.

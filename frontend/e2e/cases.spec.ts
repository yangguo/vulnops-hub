import { expect, test, type APIRequestContext, type Page } from '@playwright/test'

// The console reads the org from the org store (default and only switcher
// option: 'org-demo'), so API-created cases must live in the same org.
const ORG = 'org-demo'
const API_URL = process.env.E2E_API_URL || 'http://127.0.0.1:8010'
const OIDC_ISSUER = process.env.E2E_OIDC_ISSUER || 'http://127.0.0.1:9000'

type CaseResponse = { id: string; case_key: string; status: string }

async function issueToken(request: APIRequestContext, user: string): Promise<string> {
  const response = await request.get(`${OIDC_ISSUER}/test/token?user=${encodeURIComponent(user)}`)
  expect(response.ok()).toBeTruthy()
  const body = (await response.json()) as { access_token?: unknown }
  expect(typeof body.access_token).toBe('string')
  return body.access_token as string
}

function authHeaders(accessToken: string) {
  return { Authorization: `Bearer ${accessToken}` }
}

async function createCase(
  request: APIRequestContext,
  title: string,
  accessToken: string,
): Promise<CaseResponse> {
  const response = await request.post(`${API_URL}/api/v1/organizations/${ORG}/cases`, {
    data: { title, owner_team: 'platform', priority: 'P2' },
    headers: authHeaders(accessToken),
  })
  expect(response.ok()).toBeTruthy()
  return (await response.json()) as CaseResponse
}

async function loginAs(page: Page, user: string, returnTo = '/') {
  const targetPath = new URL(returnTo, 'http://127.0.0.1:4173').pathname
  await page.context().addCookies([
    { name: 'vulnops_test_user', value: user, url: OIDC_ISSUER, httpOnly: true },
  ])
  await page.goto(`/login?redirect=${encodeURIComponent(returnTo)}`)
  await page.getByRole('button', { name: '使用企业账号登录' }).click()
  await page.waitForURL((url: URL) => url.pathname === targetPath)
  await expect(page.getByText('OIDC 已认证')).toBeVisible()
}

test('OIDC login authenticates the console', async ({ page }) => {
  await loginAs(page, 'owner')
  await expect(page.getByText('E2E Owner')).toBeVisible()
})

test('auditor can read a case but cannot mutate it', async ({ page, request }) => {
  const ownerToken = await issueToken(request, 'owner')
  const title = `E2E auditor case ${Date.now()}`
  const created = await createCase(request, title, ownerToken)

  await loginAs(page, 'auditor', '/cases')
  await expect(page.getByText(title, { exact: true })).toBeVisible()

  await page.getByText(title, { exact: true }).click()
  await expect(page.getByText(created.case_key)).toBeVisible()
  await expect(page.getByTestId('transition-triage')).toHaveCount(0)
  await expect(page.getByText('提交复测证据…', { exact: true })).toHaveCount(0)
})

test('owner can perform a permitted transition', async ({ page, request }) => {
  const ownerToken = await issueToken(request, 'owner')
  const title = `E2E owner case ${Date.now()}`
  const created = await createCase(request, title, ownerToken)

  await loginAs(page, 'owner', '/cases')
  await expect(page.getByText(title, { exact: true })).toBeVisible()
  await page.getByText(title, { exact: true }).click()
  await expect(page.getByText(created.case_key)).toBeVisible()

  await page.getByTestId('transition-triage').click()
  await expect(page.getByText('v2')).toBeVisible()
  await expect(page.getByText('分诊', { exact: true })).toBeVisible()
})

test('expired access tokens are rejected by the API and login callback', async ({ page, request }) => {
  const expiredToken = await issueToken(request, 'expired')
  const response = await request.get(`${API_URL}/api/v1/organizations/${ORG}/cases`, {
    headers: authHeaders(expiredToken),
  })
  expect(response.status()).toBe(401)
  expect((await response.json()).code).toBe('invalid_token')

  await page.context().addCookies([
    { name: 'vulnops_test_user', value: 'expired', url: OIDC_ISSUER, httpOnly: true },
  ])
  await page.goto('/login')
  await page.getByRole('button', { name: '使用企业账号登录' }).click()
  await page.waitForURL((url: URL) => url.pathname === '/auth/callback')
  await expect(page.getByRole('alert')).toContainText('过期')
})

test('cross-organization access is denied without disclosing the case', async ({ page, request }) => {
  const ownerToken = await issueToken(request, 'owner')
  const crossOrgToken = await issueToken(request, 'cross-org')
  const title = `E2E cross-org case ${Date.now()}`
  const created = await createCase(request, title, ownerToken)

  const apiDenied = await request.get(
    `${API_URL}/api/v1/organizations/org-other/cases/${created.id}`,
    { headers: authHeaders(crossOrgToken) },
  )
  expect(apiDenied.status()).toBe(404)

  const listResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      url.pathname === `/api/v1/organizations/${ORG}/cases` &&
      response.request().method() === 'GET'
    )
  })
  await loginAs(page, 'cross-org', '/cases')
  const browserDenied = await listResponse
  expect(browserDenied.status()).toBe(404)
  expect(browserDenied.request().headers().authorization).toMatch(/^Bearer\s+/)
  await expect(page.getByText(title, { exact: true })).toHaveCount(0)
})

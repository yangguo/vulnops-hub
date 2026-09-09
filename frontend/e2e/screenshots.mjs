/**
 * Capture console screenshots for the README.
 * Drives the locally installed Edge/Chrome against the running dev servers.
 * Usage: node e2e/screenshots.mjs  (backend :8000, vite :5173, Keycloak :8082)
 */

import { chromium } from '@playwright/test'
import { mkdirSync } from 'node:fs'

const OUT = '../docs/screenshots'
mkdirSync(OUT, { recursive: true })

const SHOTS = [
  { path: '/', file: 'dashboard.png', name: '看板' },
  { path: '/cases', file: 'cases.png', name: '工单列表' },
  { path: '/source-health', file: 'source-health.png', name: '源健康' },
  { path: '/review', file: 'candidate-review.png', name: '候选审查' },
  { path: '/sboms', file: 'sbom-submit.png', name: 'SBOM 提交' },
]

async function waitFor(url, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(url)
      if (resp.ok) return
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 1000))
  }
  throw new Error(`timeout waiting for ${url}`)
}

await waitFor('http://localhost:5173/')
await waitFor('http://localhost:8000/health/live')

const channel = process.env.BROWSER_CHANNEL ?? 'msedge'
const browser = await chromium.launch({ channel, headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const page = await context.newPage()
page.on('pageerror', (e) => console.log('PAGEERROR:', String(e).slice(0, 300)))
page.on('console', (m) => {
  if (m.type() === 'error') console.log('CONSOLE-ERR:', m.text().slice(0, 250))
})
page.on('requestfailed', (r) => console.log('REQ-FAIL:', r.url().slice(0, 150)))
page.on('response', (r) => {
  if (r.status() >= 400) console.log('HTTP', r.status(), r.url().slice(0, 150))
})

// Real OIDC login through the configured identity provider
await page.goto('http://localhost:5173/login')
await page.getByRole('button', { name: '使用企业账号登录' }).click()
await page.waitForURL(/realms\/vulnops/, { timeout: 20000 })
await page.locator('#username').fill('owner-demo')
await page.locator('#password').fill('sandbox-owner-password')
await page.locator('#kc-login').click()
await page.waitForURL(/localhost:5173\/$/, { timeout: 30000 })
await page.getByRole('menuitem', { name: /工单/ }).waitFor({ timeout: 30000 })
await page.waitForLoadState('networkidle')

// SPA-internal navigation only: a full page reload drops the in-memory
// access token and bounces back to the login screen.
async function navigateMenu(name) {
  await page.getByRole('menuitem', { name }).click()
  await page.waitForLoadState('networkidle')
  await page.waitForTimeout(600)
}

// 看板 is already the post-login landing page
await page.screenshot({ path: `${OUT}/dashboard.png`, fullPage: false })
console.log('captured 看板 -> docs/screenshots/dashboard.png')

await navigateMenu('工单')
await page.screenshot({ path: `${OUT}/cases.png`, fullPage: false })
console.log('captured 工单列表 -> docs/screenshots/cases.png')

// 工单详情：行点击进入
await page.locator('.el-table__body-wrapper tbody tr').first().click()
await page.waitForURL(/\/cases\//, { timeout: 15000 })
await page.waitForLoadState('networkidle')
await page.waitForTimeout(800)
await page.screenshot({ path: `${OUT}/case-detail.png`, fullPage: false })
console.log('captured 工单详情 -> docs/screenshots/case-detail.png')

await navigateMenu('源健康')
await page.screenshot({ path: `${OUT}/source-health.png`, fullPage: false })
console.log('captured 源健康 -> docs/screenshots/source-health.png')

await navigateMenu('候选审查')
await page.screenshot({ path: `${OUT}/candidate-review.png`, fullPage: false })
console.log('captured 候选审查 -> docs/screenshots/candidate-review.png')

// SBOM 提交需要 sbom:write：以 admin-demo 在独立上下文登录后截取
const adminContext = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const adminPage = await adminContext.newPage()
await adminPage.goto('http://localhost:5173/login')
await adminPage.getByRole('button', { name: '使用企业账号登录' }).click()
await adminPage.waitForURL(/realms\/vulnops/, { timeout: 30000 })
await adminPage.locator('#username').fill('admin-demo')
await adminPage.locator('#password').fill('sandbox-admin-user-password')
await adminPage.locator('#kc-login').click()
await adminPage.waitForURL(/localhost:5173\/(sboms)?$/, { timeout: 30000 })
console.log('admin landed:', adminPage.url())
await adminPage.getByRole('menuitem', { name: /SBOM 提交/ }).click()
await adminPage.waitForLoadState('networkidle')
await adminPage.waitForTimeout(600)
await adminPage.screenshot({ path: `${OUT}/sbom-submit.png`, fullPage: false })
console.log('captured SBOM 提交 -> docs/screenshots/sbom-submit.png')
await adminContext.close()

await browser.close()
console.log('done')

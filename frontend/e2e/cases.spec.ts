import { expect, test } from '@playwright/test'

// The console reads the org from the org store (default and only switcher
// option: 'org-demo'), so the API-created case must live in the same org
// for the list/detail pages to see it.
const ORG = 'org-demo'

test('create a case via API, see it in list, walk it to triage', async ({ page, request }) => {
  const created = await request.post(`http://127.0.0.1:8010/api/v1/organizations/${ORG}/cases`, {
    data: { title: 'E2E case', owner_team: 'platform', priority: 'P2' },
  })
  expect(created.ok()).toBeTruthy()
  // The detail header renders case_key (CASE-XXXXXXXX), not the raw id.
  const { case_key } = await created.json()

  await page.goto('/cases')
  await expect(page.getByText('E2E case')).toBeVisible()

  await page.getByText('E2E case').click()
  await expect(page.getByText(case_key)).toBeVisible()

  await page.getByTestId('transition-triage').click()
  // 'v2' auto-waits for the store refresh that follows the transition. The
  // '分诊' text is ambiguous (stepper label, transition button, success toast
  // all contain it) until the refresh lands, and expect() does not retry on
  // strict-mode violations — so assert v2 first, then match 分诊 exactly.
  await expect(page.getByText('v2')).toBeVisible()
  await expect(page.getByText('分诊', { exact: true })).toBeVisible()
})

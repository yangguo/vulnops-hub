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
    localStorage.clear()
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

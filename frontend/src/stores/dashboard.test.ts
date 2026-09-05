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
  // brief's totalFor falls through to `return 20` for P3/P4, contradicting the
  // expected byPriority { P3: 0, P4: 0 }; model the intended backend here.
  if (priority === 'P3' || priority === 'P4') return 0
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

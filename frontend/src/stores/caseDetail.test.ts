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

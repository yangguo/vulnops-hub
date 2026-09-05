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
    await expect(store.decide({ type: 'risk_accepted', reason: 'waf', evidence_ids: ['e1'], requested_by: 'a', approver: 'b', approver_role: 'security_lead' })).resolves.toMatchObject({ id: 'rd1' })
  })

  it('submits verification payload', async () => {
    vi.mocked(apiClient.submitVerification).mockResolvedValue({ id: 'v1', status: 'closed' } as never)
    const store = useCaseDetailStore()
    useOrgStore().setOrg('acme')
    await store.fetchAll('c1')
    await store.verify({ method: 'scanner', coverage: { status: 'complete', scope_version: 'v2' }, evidence_ids: [] })
    expect(apiClient.submitVerification).toHaveBeenCalledWith('acme', 'c1', expect.objectContaining({ method: 'scanner' }))
    await expect(store.verify({ method: 'scanner', coverage: { status: 'complete', scope_version: 'v2' }, evidence_ids: [] })).resolves.toMatchObject({ id: 'v1', status: 'closed' })
  })
})

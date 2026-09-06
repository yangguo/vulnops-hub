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

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  const promise = new Promise<T>((resolvePending) => {
    resolve = resolvePending
  })
  return { promise, resolve }
}

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

  it('ignores responses that resolve after the store is cleared', async () => {
    type Detail = Awaited<ReturnType<typeof apiClient.getCase>>
    type Allowed = Awaited<ReturnType<typeof apiClient.getAllowed>>
    type Decisions = Awaited<ReturnType<typeof apiClient.listRiskDecisions>>
    type Verifications = Awaited<ReturnType<typeof apiClient.listVerifications>>
    const detail = deferred<Detail>()
    const allowed = deferred<Allowed>()
    const decisions = deferred<Decisions>()
    const verifications = deferred<Verifications>()
    vi.mocked(apiClient.getCase).mockReturnValue(detail.promise)
    vi.mocked(apiClient.getAllowed).mockReturnValue(allowed.promise)
    vi.mocked(apiClient.listRiskDecisions).mockReturnValue(decisions.promise)
    vi.mocked(apiClient.listVerifications).mockReturnValue(verifications.promise)

    const store = useCaseDetailStore()
    const fetchPromise = store.fetchAll('c1')
    const generationBeforeClear = store.generation
    store.clear()

    detail.resolve({ id: 'alice-case', status: 'triage', version: 2 } as never)
    allowed.resolve({ case_id: 'alice-case', status: 'triage', allowed: ['assigned'], current: 'triage' })
    decisions.resolve({ items: [{ id: 'alice-decision' }] } as never)
    verifications.resolve({ items: [{ id: 'alice-verification' }] } as never)
    await fetchPromise

    expect(store.generation).toBe(generationBeforeClear + 1)
    expect(store.detail).toBeNull()
    expect(store.allowed).toEqual([])
    expect(store.decisions).toEqual([])
    expect(store.verifications).toEqual([])
    expect(store.loading).toBe(false)
  })
})

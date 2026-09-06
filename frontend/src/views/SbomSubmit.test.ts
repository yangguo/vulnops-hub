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
      id: 'sbom_1',
      sbom_id: 'sbom_1',
      submission_id: 'sub_sbom_1',
      content_sha256: 'abc',
      content_hash: 'abc',
      digest: 'abc',
      status: 'accepted',
      received_at: '2099-01-01T00:00:00Z',
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

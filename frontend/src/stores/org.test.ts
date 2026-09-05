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

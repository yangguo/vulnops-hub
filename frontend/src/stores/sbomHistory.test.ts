import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { SBOM_HISTORY_STORAGE_KEY, useSbomHistoryStore, type SbomHistoryEntry } from './sbomHistory'

const entry: SbomHistoryEntry = {
  at: '2026-01-01T00:00:00Z',
  org: 'acme',
  sbom_id: 'sbom-1',
  sha: 'abc123',
}

describe('SBOM history store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('loads persisted history into live Pinia state', () => {
    localStorage.setItem(SBOM_HISTORY_STORAGE_KEY, JSON.stringify([entry]))

    const store = useSbomHistoryStore()

    expect(store.history).toEqual([entry])
  })

  it('clears persisted and live history while advancing its generation', () => {
    const store = useSbomHistoryStore()
    store.record(entry, store.generation)
    const generationBeforeClear = store.generation

    store.clear()

    expect(store.history).toEqual([])
    expect(localStorage.getItem(SBOM_HISTORY_STORAGE_KEY)).toBeNull()
    expect(store.generation).toBe(generationBeforeClear + 1)
  })

  it('rejects a write captured before cleanup', () => {
    const store = useSbomHistoryStore()
    const staleGeneration = store.generation
    store.clear()

    expect(store.record(entry, staleGeneration)).toBe(false)
    expect(store.history).toEqual([])
    expect(localStorage.getItem(SBOM_HISTORY_STORAGE_KEY)).toBeNull()
  })
})

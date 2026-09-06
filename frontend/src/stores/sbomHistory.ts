import { defineStore } from 'pinia'

export const SBOM_HISTORY_STORAGE_KEY = 'vulnops.sbom-history'

export interface SbomHistoryEntry {
  at: string
  org: string
  sbom_id: string
  sha: string
}

function isSbomHistoryEntry(value: unknown): value is SbomHistoryEntry {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate.at === 'string' &&
    typeof candidate.org === 'string' &&
    typeof candidate.sbom_id === 'string' &&
    typeof candidate.sha === 'string'
  )
}

function loadHistory(): SbomHistoryEntry[] {
  try {
    const raw = localStorage.getItem(SBOM_HISTORY_STORAGE_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter(isSbomHistoryEntry).slice(0, 20) : []
  } catch {
    return []
  }
}

function persistHistory(history: SbomHistoryEntry[]): void {
  try {
    localStorage.setItem(SBOM_HISTORY_STORAGE_KEY, JSON.stringify(history))
  } catch {
    // Ignore storage failures in restricted browser contexts.
  }
}

export const useSbomHistoryStore = defineStore('sbomHistory', {
  state: () => ({
    history: loadHistory(),
    generation: 0,
  }),
  actions: {
    clear() {
      this.history = []
      this.generation += 1
      try {
        localStorage.removeItem(SBOM_HISTORY_STORAGE_KEY)
      } catch {
        // Ignore storage failures in restricted browser contexts.
      }
    },
    record(entry: SbomHistoryEntry, generation: number): boolean {
      if (generation !== this.generation) return false
      this.history = [entry, ...this.history].slice(0, 20)
      persistHistory(this.history)
      return true
    },
  },
})

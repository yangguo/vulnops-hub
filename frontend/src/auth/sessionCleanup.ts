import { useOrgStore } from '../stores/org'
import { SBOM_HISTORY_STORAGE_KEY, useSbomHistoryStore } from '../stores/sbomHistory'

export { SBOM_HISTORY_STORAGE_KEY }

/** Purge browser state that must not survive logout / auth loss across users. */
export function clearUserBoundBrowserState(): void {
  try {
    useOrgStore().clear()
  } catch {
    try {
      localStorage.removeItem('vulnops.org')
    } catch {
      // ignore storage failures in restricted environments
    }
  }
  try {
    useSbomHistoryStore().clear()
  } catch {
    // Pinia may be unavailable in some unit contexts; still drop the key.
    try {
      localStorage.removeItem(SBOM_HISTORY_STORAGE_KEY)
    } catch {
      // ignore
    }
  }
}

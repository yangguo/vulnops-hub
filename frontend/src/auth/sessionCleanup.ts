import { useOrgStore } from '../stores/org'

export const SBOM_HISTORY_STORAGE_KEY = 'vulnops.sbom-history'

/** Purge browser state that must not survive logout / auth loss across users. */
export function clearUserBoundBrowserState(): void {
  try {
    localStorage.removeItem(SBOM_HISTORY_STORAGE_KEY)
  } catch {
    // ignore storage failures in restricted environments
  }
  try {
    useOrgStore().clear()
  } catch {
    // Pinia may be unavailable in some unit contexts; still drop the key.
    try {
      localStorage.removeItem('vulnops.org')
    } catch {
      // ignore
    }
  }
}

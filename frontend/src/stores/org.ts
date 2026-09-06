import { defineStore } from 'pinia'

export const ORG_STORAGE_KEY = 'vulnops.org'
const DEFAULT_ORG = 'org-demo'

export const useOrgStore = defineStore('org', {
  state: () => ({ org: localStorage.getItem(ORG_STORAGE_KEY) || DEFAULT_ORG }),
  actions: {
    setOrg(org: string) {
      this.org = org
      localStorage.setItem(ORG_STORAGE_KEY, org)
    },
    clear() {
      this.org = DEFAULT_ORG
      localStorage.removeItem(ORG_STORAGE_KEY)
    },
  },
})

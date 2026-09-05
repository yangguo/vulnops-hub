import { defineStore } from 'pinia'

const STORAGE_KEY = 'vulnops.org'

export const useOrgStore = defineStore('org', {
  state: () => ({ org: localStorage.getItem(STORAGE_KEY) || 'org-demo' }),
  actions: {
    setOrg(org: string) {
      this.org = org
      localStorage.setItem(STORAGE_KEY, org)
    },
  },
})

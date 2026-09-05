import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import type { CaseDetail } from '../api/types'
import { useOrgStore } from './org'

export const useCasesStore = defineStore('cases', {
  state: () => ({
    items: [] as CaseDetail[],
    total: 0,
    page: 1,
    pageSize: 20,
    sort: '-created_at',
    loading: false,
    filters: { status: '', priority: '', ownerTeam: '', slaBreached: false },
  }),
  actions: {
    async fetch() {
      this.loading = true
      try {
        const org = useOrgStore().org
        const qs = new URLSearchParams()
        if (this.filters.status) qs.set('status', this.filters.status)
        if (this.filters.priority) qs.set('priority', this.filters.priority)
        if (this.filters.ownerTeam) qs.set('owner_team', this.filters.ownerTeam)
        if (this.filters.slaBreached) qs.set('sla_breached', 'true')
        qs.set('page', String(this.page))
        qs.set('page_size', String(this.pageSize))
        qs.set('sort', this.sort)
        const data = await apiClient.listCases(org, `?${qs.toString()}`)
        this.items = data.items
        this.total = data.total
      } finally {
        this.loading = false
      }
    },
    resetFilters() {
      this.filters = { status: '', priority: '', ownerTeam: '', slaBreached: false }
      this.page = 1
    },
  },
})

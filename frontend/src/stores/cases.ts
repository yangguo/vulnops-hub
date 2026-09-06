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
    generation: 0,
    filters: { status: '', priority: '', ownerTeam: '', slaBreached: false },
  }),
  actions: {
    clear() {
      this.items = []
      this.total = 0
      this.page = 1
      this.pageSize = 20
      this.sort = '-created_at'
      this.loading = false
      this.filters = { status: '', priority: '', ownerTeam: '', slaBreached: false }
      this.generation += 1
    },
    async fetch() {
      const generation = this.generation
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
        if (generation !== this.generation) return
        this.items = data.items
        this.total = data.total
      } finally {
        if (generation === this.generation) this.loading = false
      }
    },
    resetFilters() {
      this.filters = { status: '', priority: '', ownerTeam: '', slaBreached: false }
      this.page = 1
    },
  },
})

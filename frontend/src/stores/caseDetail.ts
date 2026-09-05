import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import type { CaseDetail, RiskDecisionItem, VerificationItem } from '../api/types'
import { useOrgStore } from './org'

export const useCaseDetailStore = defineStore('caseDetail', {
  state: () => ({
    detail: null as CaseDetail | null,
    allowed: [] as string[],
    decisions: [] as RiskDecisionItem[],
    verifications: [] as VerificationItem[],
    loading: false,
  }),
  actions: {
    async fetchAll(caseId: string) {
      this.loading = true
      try {
        const org = useOrgStore().org
        const [detail, allowed, decisions, verifications] = await Promise.all([
          apiClient.getCase(org, caseId),
          apiClient.getAllowed(org, caseId),
          apiClient.listRiskDecisions(org, caseId),
          apiClient.listVerifications(org, caseId),
        ])
        this.detail = detail
        this.allowed = allowed.allowed
        this.decisions = decisions.items
        this.verifications = verifications.items
      } finally {
        this.loading = false
      }
    },
    async refresh() {
      if (this.detail) await this.fetchAll(this.detail.id)
    },
  },
})

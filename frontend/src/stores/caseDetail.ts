import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import type { CaseDetail, RiskDecisionItem, RiskDecisionRequest, VerificationItem } from '../api/types'
import { useOrgStore } from './org'

export const useCaseDetailStore = defineStore('caseDetail', {
  state: () => ({
    detail: null as CaseDetail | null,
    allowed: [] as string[],
    decisions: [] as RiskDecisionItem[],
    verifications: [] as VerificationItem[],
    loading: false,
    generation: 0,
  }),
  actions: {
    clear() {
      this.detail = null
      this.allowed = []
      this.decisions = []
      this.verifications = []
      this.loading = false
      this.generation += 1
    },
    async fetchAll(caseId: string) {
      const generation = this.generation
      this.loading = true
      try {
        const org = useOrgStore().org
        const [detail, allowed, decisions, verifications] = await Promise.all([
          apiClient.getCase(org, caseId),
          apiClient.getAllowed(org, caseId),
          apiClient.listRiskDecisions(org, caseId),
          apiClient.listVerifications(org, caseId),
        ])
        if (generation !== this.generation) return
        this.detail = detail
        this.allowed = allowed.allowed
        this.decisions = decisions.items
        this.verifications = verifications.items
      } finally {
        if (generation === this.generation) this.loading = false
      }
    },
    async refresh() {
      if (this.detail) await this.fetchAll(this.detail.id)
    },
    async transition(target: string, reason?: string) {
      const generation = this.generation
      const org = useOrgStore().org
      const detail = this.detail
      if (!detail) return
      await apiClient.transition(org, detail.id, detail.version, target, reason)
      if (generation !== this.generation) return
      await this.fetchAll(detail.id)
    },
    async decide(payload: RiskDecisionRequest) {
      const generation = this.generation
      const org = useOrgStore().org
      const detail = this.detail
      if (!detail) return
      const decision = await apiClient.createRiskDecision(org, detail.id, payload)
      if (generation === this.generation) await this.fetchAll(detail.id)
      return decision
    },
    async verify(payload: Record<string, unknown>) {
      const generation = this.generation
      const org = useOrgStore().org
      const detail = this.detail
      if (!detail) return
      const verification = await apiClient.submitVerification(org, detail.id, payload)
      if (generation === this.generation) await this.fetchAll(detail.id)
      return verification
    },
  },
})

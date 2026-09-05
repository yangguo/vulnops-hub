import { defineStore } from 'pinia'
import { apiClient } from '../api/client'
import { useOrgStore } from './org'

export const useDashboardStore = defineStore('dashboard', {
  state: () => ({
    byPriority: { P0: 0, P1: 0, P2: 0, P3: 0, P4: 0 } as Record<string, number>,
    breached: 0,
    openCount: 0,
    p0p1Open: 0,
    avgCloseDays: null as number | null,
    slaTrend: [] as Array<{ date: string; rate: number }>,
    loading: false,
  }),
  actions: {
    async fetch() {
      this.loading = true
      try {
        const org = useOrgStore().org
        const count = async (query: string) =>
          (await apiClient.listCases(org, `?page_size=1&${query}`)).total

        const priorities = ['P0', 'P1', 'P2', 'P3', 'P4'] as const
        const counts = await Promise.all(priorities.map((p) => count(`priority=${p}`)))
        priorities.forEach((p, i) => {
          this.byPriority[p] = counts[i]
        })

        const [all, closed, riskAccepted, notApplicable] = await Promise.all([
          count(''),
          count('status=closed'),
          count('status=risk_accepted'),
          count('status=not_applicable'),
        ])
        this.openCount = all - closed - riskAccepted - notApplicable
        this.breached = await count('sla_breached=true')

        // P0/P1 未关闭 = 各自总数 − 已关闭 − 风险接受 − 不适用
        const highPriOpen = async (p: string) => {
          const [total, c, r, n] = await Promise.all([
            count(`priority=${p}`),
            count(`priority=${p}&status=closed`),
            count(`priority=${p}&status=risk_accepted`),
            count(`priority=${p}&status=not_applicable`),
          ])
          return total - c - r - n
        }
        const [p0, p1] = await Promise.all([highPriOpen('P0'), highPriOpen('P1')])
        this.p0p1Open = p0 + p1

        // 平均关闭时长：从最近 100 条已关闭工单估算（spec §5.2 的 MVP 简化）
        const recent = await apiClient.listCases(org, '?page_size=100&status=closed&sort=-updated_at')
        const durations = recent.items
          .filter((c) => c.created_at && c.updated_at)
          .map((c) => (new Date(c.updated_at!).getTime() - new Date(c.created_at!).getTime()) / 86_400_000)
        this.avgCloseDays =
          durations.length > 0
            ? Math.round((durations.reduce((a, b) => a + b, 0) / durations.length) * 10) / 10
            : null

        // SLA 达成率趋势：按关闭日分桶，on-time = updated_at <= due_at
        const trend = new Map<string, { onTime: number; total: number }>()
        for (const c of recent.items) {
          if (!c.updated_at || !c.due_at) continue
          const day = c.updated_at.slice(0, 10)
          const bucket = trend.get(day) ?? { onTime: 0, total: 0 }
          bucket.total += 1
          if (new Date(c.updated_at).getTime() <= new Date(c.due_at).getTime()) bucket.onTime += 1
          trend.set(day, bucket)
        }
        this.slaTrend = [...trend.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([date, b]) => ({ date, rate: Math.round((b.onTime / b.total) * 100) }))
      } finally {
        this.loading = false
      }
    },
  },
})

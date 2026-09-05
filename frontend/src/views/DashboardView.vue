<template>
  <el-row
    v-loading="store.loading"
    :gutter="16"
  >
    <el-col :span="6">
      <el-card>
        <el-statistic
          title="未关闭工单"
          :value="store.openCount"
        />
      </el-card>
    </el-col>
    <el-col :span="6">
      <el-card>
        <el-statistic
          title="SLA 已超时"
          :value="store.breached"
          :value-style="{ color: '#f56c6c' }"
        />
      </el-card>
    </el-col>
    <el-col :span="6">
      <el-card>
        <el-statistic
          title="P0·P1 未关闭"
          :value="store.p0p1Open"
        />
      </el-card>
    </el-col>
    <el-col :span="6">
      <el-card>
        <el-statistic
          title="平均关闭时长（近100条）"
          :value="store.avgCloseDays ?? 0"
          :precision="1"
          suffix=" 天"
        />
      </el-card>
    </el-col>
  </el-row>

  <el-row
    :gutter="16"
    class="charts"
  >
    <el-col :span="12">
      <el-card header="优先级分布">
        <BaseChart
          :option="pieOption"
          height="320px"
        />
      </el-card>
    </el-col>
    <el-col :span="12">
      <el-card header="SLA 达成趋势（按天，近100条已关闭）">
        <BaseChart
          :option="trendOption"
          height="320px"
        />
      </el-card>
    </el-col>
  </el-row>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from 'vue'
import type { EChartsOption } from 'echarts'
import { useDashboardStore } from '../stores/dashboard'
import BaseChart from '../components/BaseChart.vue'

const store = useDashboardStore()

const pieOption = computed<EChartsOption>(() => ({
  tooltip: {},
  series: [
    {
      type: 'pie',
      radius: ['40%', '70%'],
      data: Object.entries(store.byPriority).map(([name, value]) => ({ name, value })),
    },
  ],
}))

const trendOption = computed<EChartsOption>(() => ({
  tooltip: { formatter: '{b}: {c}%' },
  xAxis: { type: 'category', data: store.slaTrend.map((p) => p.date) },
  yAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } },
  series: [{ type: 'line', data: store.slaTrend.map((p) => p.rate), areaStyle: {} }],
}))

onMounted(() => {
  store.fetch()
  timer = window.setInterval(() => {
    if (document.visibilityState === 'visible') store.fetch()
  }, 30_000)
})
let timer: number | undefined
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<style scoped>
.charts { margin-top: 16px; }
</style>

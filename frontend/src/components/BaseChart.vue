<template>
  <div
    ref="el"
    class="base-chart"
    :style="{ height }"
  />
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import type { EChartsOption } from 'echarts'

const props = defineProps<{ option: EChartsOption; height?: string }>()
const el = ref<HTMLDivElement>()
let chart: echarts.ECharts | null = null

onMounted(() => {
  chart = echarts.init(el.value!)
  chart.setOption(props.option)
  window.addEventListener('resize', resize)
})
watch(
  () => props.option,
  (option) => chart?.setOption(option, true),
  { deep: true },
)
function resize() {
  chart?.resize()
}
onBeforeUnmount(() => {
  window.removeEventListener('resize', resize)
  chart?.dispose()
})
</script>

<style scoped>
.base-chart { width: 100%; }
</style>

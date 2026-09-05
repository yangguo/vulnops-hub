<template>
  <span
    class="sla-badge"
    :class="{ 'sla-breached': breached }"
  >
    {{ breached ? '⚠ 已超时' : `⏱ 剩 ${remaining}` }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ dueAt: string | null; breached: boolean }>()

const remaining = computed(() => {
  if (!props.dueAt) return '无 SLA'
  const ms = new Date(props.dueAt).getTime() - Date.now()
  if (ms <= 0) return '已超时'
  const hours = Math.floor(ms / 3600000)
  if (hours < 48) return `${hours}h`
  return `${Math.floor(hours / 24)}d${hours % 24}h`
})
</script>

<style scoped>
.sla-badge { font-size: 12px; color: var(--el-color-success); }
.sla-badge.sla-breached { color: var(--el-color-danger); font-weight: 600; }
</style>

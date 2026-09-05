<template>
  <el-tag
    :type="map[status] ?? 'info'"
    size="small"
  >
    {{ label }}
  </el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ status: string }>()

const LABELS: Record<string, string> = {
  new: '新建',
  triage: '分诊',
  assigned: '已分派',
  in_progress: '整改中',
  awaiting_verification: '待复测',
  closed: '已关闭',
  risk_accepted: '风险已接受',
  not_applicable: '不适用',
  reopened: '已重开',
}
const TYPES: Record<string, string> = {
  new: 'info',
  triage: 'warning',
  assigned: 'primary',
  in_progress: 'primary',
  awaiting_verification: 'warning',
  closed: 'success',
  risk_accepted: 'danger',
  not_applicable: 'info',
  reopened: 'danger',
}
const label = computed(() => LABELS[props.status] ?? props.status)
const map = TYPES
</script>

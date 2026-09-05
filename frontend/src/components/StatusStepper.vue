<template>
  <div>
    <el-alert
      v-if="sideLabel"
      :title="`当前状态：${sideLabel}`"
      type="warning"
      show-icon
      :closable="false"
      class="side-alert"
    />
    <el-steps
      :active="active"
      align-center
      finish-status="success"
    >
      <el-step
        v-for="s in STEPS"
        :key="s.value"
        :title="s.label"
      />
    </el-steps>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ElAlert, ElStep, ElSteps } from 'element-plus'

const props = defineProps<{ status: string }>()

const STEPS = [
  { value: 'new', label: '新建' },
  { value: 'triage', label: '分诊' },
  { value: 'assigned', label: '已分派' },
  { value: 'in_progress', label: '整改中' },
  { value: 'awaiting_verification', label: '待复测' },
  { value: 'closed', label: '已关闭' },
] as const

const SIDE_LABELS: Record<string, string> = {
  risk_accepted: '风险已接受',
  not_applicable: '不适用',
  reopened: '已重开（重新进入分诊）',
}

const active = computed(() => {
  const idx = STEPS.findIndex((s) => s.value === props.status)
  if (idx >= 0) return idx
  return 1 // side states branch off triage
})
const sideLabel = computed(() => SIDE_LABELS[props.status] ?? null)
</script>

<style scoped>
.side-alert { margin-bottom: 10px; }
</style>

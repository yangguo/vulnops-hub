<template>
  <div class="action-bar">
    <template
      v-for="target in store.allowed"
      :key="target"
    >
      <el-button
        v-if="target === 'risk_accepted'"
        type="warning"
        plain
        @click="riskMode = 'risk_accepted'; riskVisible = true"
      >
        接受风险…
      </el-button>
      <el-button
        v-else-if="target === 'not_applicable'"
        type="info"
        plain
        @click="riskMode = 'not_applicable'; riskVisible = true"
      >
        标记不适用…
      </el-button>
      <el-button
        v-else
        type="primary"
        plain
        :data-test="`transition-${target}`"
        @click="doTransition(target)"
      >
        流转到 {{ TARGET_LABELS[target] ?? target }}
      </el-button>
    </template>

    <el-button
      v-if="store.detail?.status === 'awaiting_verification'"
      type="success"
      plain
      @click="$emit('verify')"
    >
      提交复测证据…
    </el-button>

    <RiskDecisionDrawer
      v-model="riskVisible"
      :mode="riskMode"
    />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElButton, ElMessage, ElMessageBox } from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'
import { ApiError } from '../api/client'
import RiskDecisionDrawer from './RiskDecisionDrawer.vue'

defineEmits<{ verify: [] }>()

const store = useCaseDetailStore()
const riskVisible = ref(false)
const riskMode = ref<'risk_accepted' | 'not_applicable'>('risk_accepted')

const TARGET_LABELS: Record<string, string> = {
  triage: '分诊',
  assigned: '已分派',
  in_progress: '整改中',
  awaiting_verification: '待复测',
  closed: '已关闭',
  reopened: '重开',
}

async function doTransition(target: string) {
  try {
    await store.transition(target)
    ElMessage.success(`已流转到 ${TARGET_LABELS[target] ?? target}`)
  } catch (err) {
    if (err instanceof ApiError && err.status === 412) {
      const confirmed = await ElMessageBox.confirm('工单已被他人修改。刷新后重试？', '版本冲突', {
        confirmButtonText: '刷新',
        cancelButtonText: '取消',
        type: 'warning',
      }).catch(() => null)
      if (confirmed == null) return
      await store.refresh()
      return
    }
    ElMessage.error(err instanceof Error ? err.message : '流转失败')
  }
}
</script>

<style scoped>
.action-bar { margin: 16px 0; display: flex; gap: 8px; }
</style>

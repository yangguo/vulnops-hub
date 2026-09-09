<template>
  <el-card header="候选暴露审查">
    <el-table
      :data="items"
      size="small"
      :loading="loading"
    >
      <el-table-column
        prop="vulnerability_id"
        label="漏洞"
        width="180"
      />
      <el-table-column
        prop="match_class"
        label="匹配"
        width="140"
      />
      <el-table-column
        prop="confidence"
        label="置信度"
        width="100"
      >
        <template #default="{ row }">
          {{ row.confidence.toFixed(2) }}
        </template>
      </el-table-column>
      <el-table-column
        prop="priority"
        label="优先级"
        width="100"
      >
        <template #default="{ row }">
          {{ row.priority ?? '—' }}
        </template>
      </el-table-column>
      <el-table-column
        prop="detection_context"
        label="检测来源"
        show-overflow-tooltip
      />
      <el-table-column
        label="操作"
        width="220"
      >
        <template #default="{ row }">
          <el-button
            size="small"
            type="primary"
            :disabled="busyId === row.id"
            @click="openDecision(row as ExposureItem, 'confirmed')"
          >
            确认
          </el-button>
          <el-button
            size="small"
            type="warning"
            :disabled="busyId === row.id"
            @click="openDecision(row as ExposureItem, 'not_affected')"
          >
            不受影响
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog
      v-model="dialogVisible"
      :title="decisionTitle"
      width="480px"
    >
      <div class="decision-target">
        {{ current?.vulnerability_id }}（{{ current?.detection_context ?? '无来源' }}）
      </div>
      <el-input
        v-model="reason"
        type="textarea"
        :rows="3"
        placeholder="审查理由（必填，写入审计）"
      />
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="submitting"
          :disabled="!reason.trim()"
          @click="submitDecision"
        >
          提交
        </el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import {
  ElButton,
  ElCard,
  ElDialog,
  ElInput,
  ElMessage,
  ElTable,
  ElTableColumn,
} from 'element-plus'
import { apiClient, ApiError } from '../api/client'
import type { ExposureItem } from '../api/types'
import { useOrgStore } from '../stores/org'

const items = ref<ExposureItem[]>([])
const loading = ref(false)
const busyId = ref('')
const dialogVisible = ref(false)
const submitting = ref(false)
const current = ref<ExposureItem | null>(null)
const decision = ref<'confirmed' | 'not_affected'>('confirmed')
const reason = ref('')
const orgStore = useOrgStore()

const decisionTitle = ref('审查决定')

function openDecision(row: ExposureItem, kind: 'confirmed' | 'not_affected') {
  current.value = row
  decision.value = kind
  decisionTitle.value = kind === 'confirmed' ? '确认暴露' : '标记不受影响'
  reason.value = ''
  dialogVisible.value = true
}

async function load() {
  loading.value = true
  try {
    const resp = await apiClient.listExposures(orgStore.org, 'candidate')
    items.value = resp.items
  } catch (err) {
    const message = err instanceof ApiError ? `${err.code}: ${err.message}` : String(err)
    ElMessage.error(message)
  } finally {
    loading.value = false
  }
}

async function submitDecision() {
  if (!current.value) return
  busyId.value = current.value.id
  submitting.value = true
  try {
    await apiClient.reviewExposure(orgStore.org, current.value.id, {
      decision: decision.value,
      reason: reason.value.trim(),
    })
    ElMessage.success('审查已记录')
    dialogVisible.value = false
    await load()
  } catch (err) {
    const message = err instanceof ApiError ? `${err.code}: ${err.message}` : String(err)
    ElMessage.error(message)
  } finally {
    submitting.value = false
    busyId.value = ''
  }
}

onMounted(load)
</script>

<style scoped>
.decision-target {
  margin-bottom: 10px;
  font-weight: 600;
}
</style>

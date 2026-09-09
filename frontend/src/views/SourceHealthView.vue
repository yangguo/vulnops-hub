<template>
  <el-card header="情报与证据源健康">
    <el-alert
      v-if="degraded.length"
      type="warning"
      :closable="false"
      class="degraded-alert"
      :title="`降级源：${degraded.join('、')}`"
    />
    <el-table
      :data="items"
      size="small"
      :loading="loading"
    >
      <el-table-column
        prop="source"
        label="来源"
        width="160"
      />
      <el-table-column
        label="新鲜度"
        width="120"
      >
        <template #default="{ row }">
          <el-tag
            :type="tagType(row.freshness)"
            size="small"
          >
            {{ row.freshness }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        prop="last_success_at"
        label="最近成功"
        width="200"
      >
        <template #default="{ row }">
          {{ row.last_success_at ?? '—' }}
        </template>
      </el-table-column>
      <el-table-column
        prop="last_checked_at"
        label="最近检查"
        width="200"
      >
        <template #default="{ row }">
          {{ row.last_checked_at ?? '—' }}
        </template>
      </el-table-column>
      <el-table-column label="游标">
        <template #default="{ row }">
          <span
            v-if="row.cursor"
            class="cursor"
          >{{ row.cursor }}</span>
          <span v-else>—</span>
        </template>
      </el-table-column>
      <el-table-column label="错误">
        <template #default="{ row }">
          <el-tooltip
            v-if="row.last_error"
            :content="row.last_error"
            placement="top"
          >
            <el-tag
              type="danger"
              size="small"
            >
              有错误
            </el-tag>
          </el-tooltip>
          <span v-else>—</span>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  ElAlert,
  ElCard,
  ElMessage,
  ElTable,
  ElTableColumn,
  ElTag,
  ElTooltip,
} from 'element-plus'
import { apiClient, ApiError } from '../api/client'
import type { SourceHealthItem } from '../api/types'
import { useOrgStore } from '../stores/org'

const items = ref<SourceHealthItem[]>([])
const loading = ref(false)
const orgStore = useOrgStore()

const degraded = computed(() =>
  items.value
    .filter((i) => i.freshness === 'stale' || i.freshness === 'degraded')
    .map((i) => i.source),
)

function tagType(freshness: string): 'success' | 'warning' | 'danger' | 'info' {
  if (freshness === 'fresh') return 'success'
  if (freshness === 'degraded') return 'warning'
  if (freshness === 'stale') return 'danger'
  return 'info'
}

onMounted(async () => {
  loading.value = true
  try {
    const resp = await apiClient.listSourceHealth(orgStore.org)
    items.value = resp.items
  } catch (err) {
    const message = err instanceof ApiError ? `${err.code}: ${err.message}` : String(err)
    ElMessage.error(message)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.degraded-alert {
  margin-bottom: 12px;
}
.cursor {
  font-family: monospace;
  font-size: 12px;
}
</style>

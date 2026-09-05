<template>
  <div class="filters">
    <el-select
      v-model="store.filters.status"
      placeholder="状态"
      clearable
      style="width: 150px"
      @change="reload"
    >
      <el-option
        v-for="(label, value) in STATUS_OPTIONS"
        :key="value"
        :label="label"
        :value="value"
      />
    </el-select>
    <el-select
      v-model="store.filters.priority"
      placeholder="优先级"
      clearable
      style="width: 120px"
      @change="reload"
    >
      <el-option
        v-for="p in ['P0', 'P1', 'P2', 'P3', 'P4']"
        :key="p"
        :label="p"
        :value="p"
      />
    </el-select>
    <el-input
      v-model="store.filters.ownerTeam"
      placeholder="归属团队"
      clearable
      style="width: 160px"
      @change="reload"
    />
    <el-checkbox
      v-model="store.filters.slaBreached"
      label="仅看 SLA 超时"
      @change="reload"
    />
    <el-select
      v-model="store.sort"
      style="width: 140px"
      @change="reload"
    >
      <el-option
        label="最近创建"
        value="-created_at"
      />
      <el-option
        label="最早到期"
        value="due_at"
      />
      <el-option
        label="优先级"
        value="priority"
      />
    </el-select>
    <el-button @click="store.resetFilters(); reload()">
      重置
    </el-button>
  </div>

  <el-table
    v-loading="store.loading"
    :data="store.items"
    class="case-table"
    @row-click="openDetail"
  >
    <el-table-column
      prop="case_key"
      label="Case Key"
      width="150"
    />
    <el-table-column
      prop="title"
      label="标题"
      min-width="220"
      show-overflow-tooltip
    />
    <el-table-column
      label="状态"
      width="120"
    >
      <template #default="{ row }">
        <StatusTag :status="row.status" />
      </template>
    </el-table-column>
    <el-table-column
      label="优先级"
      width="80"
    >
      <template #default="{ row }">
        <PriorityTag :priority="row.priority" />
      </template>
    </el-table-column>
    <el-table-column
      prop="owner_team"
      label="团队"
      width="120"
    />
    <el-table-column
      prop="assignee"
      label="负责人"
      width="110"
    />
    <el-table-column
      label="SLA"
      width="140"
    >
      <template #default="{ row }">
        <SlaBadge
          :due-at="row.due_at"
          :breached="row.sla_breached"
        />
      </template>
    </el-table-column>
    <el-table-column
      prop="version"
      label="版本"
      width="70"
    />
  </el-table>

  <el-pagination
    v-model:current-page="store.page"
    :page-size="store.pageSize"
    :total="store.total"
    layout="prev, pager, next, total"
    class="pager"
    @current-change="store.fetch()"
  />
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useCasesStore } from '../stores/cases'
import type { CaseDetail } from '../api/types'
import PriorityTag from '../components/PriorityTag.vue'
import StatusTag from '../components/StatusTag.vue'
import SlaBadge from '../components/SlaBadge.vue'

const store = useCasesStore()
const router = useRouter()

const STATUS_OPTIONS: Record<string, string> = {
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

function reload() {
  store.page = 1
  store.fetch()
}

function openDetail(row: CaseDetail) {
  router.push(`/cases/${row.id}`)
}

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
.filters { display: flex; gap: 12px; align-items: center; margin-bottom: 14px; }
.case-table { cursor: pointer; }
.pager { margin-top: 14px; justify-content: flex-end; }
</style>

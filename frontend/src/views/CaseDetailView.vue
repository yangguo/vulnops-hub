<template>
  <div
    v-loading="store.loading"
    class="detail"
  >
    <template v-if="store.detail">
      <div class="detail-header">
        <el-page-header @back="router.back()">
          <template #content>
            <span class="case-key">{{ store.detail.case_key }}</span>
            <span class="case-title">{{ store.detail.title }}</span>
            <PriorityTag :priority="store.detail.priority" />
            <SlaBadge
              :due-at="store.detail.due_at ?? null"
              :breached="store.detail.sla_breached"
            />
          </template>
        </el-page-header>
      </div>

      <StatusStepper :status="store.detail.status" />

      <CaseActionBar @verify="verifyVisible = true" />

      <el-row
        :gutter="20"
        class="detail-body"
      >
        <el-col :span="17">
          <el-tabs v-model="tab">
            <el-tab-pane
              label="暴露面"
              name="exposures"
            >
              <el-empty
                v-if="!store.detail.exposures?.length"
                description="无暴露面记录"
              />
              <el-table
                v-else
                :data="exposureRows"
              >
                <el-table-column
                  prop="id"
                  label="Exposure ID"
                />
              </el-table>
            </el-tab-pane>
            <el-tab-pane
              :label="`风险决策 (${store.decisions.length})`"
              name="decisions"
            >
              <el-empty
                v-if="!store.decisions.length"
                description="无风险决策"
              />
              <el-table
                v-else
                :data="store.decisions"
              >
                <el-table-column
                  prop="type"
                  label="类型"
                  width="140"
                />
                <el-table-column
                  prop="status"
                  label="状态"
                  width="140"
                />
                <el-table-column
                  prop="reason"
                  label="原因"
                  min-width="180"
                  show-overflow-tooltip
                />
                <el-table-column
                  prop="approver"
                  label="审批人"
                  width="110"
                />
                <el-table-column
                  prop="expires_at"
                  label="过期时间"
                  width="180"
                />
                <el-table-column
                  prop="created_at"
                  label="创建时间"
                  width="180"
                />
              </el-table>
            </el-tab-pane>
            <el-tab-pane
              :label="`复测记录 (${store.verifications.length})`"
              name="verifications"
            >
              <el-empty
                v-if="!store.verifications.length"
                description="无复测记录"
              />
              <el-table
                v-else
                :data="store.verifications"
              >
                <el-table-column
                  prop="method"
                  label="方式"
                  width="150"
                />
                <el-table-column
                  prop="status"
                  label="结果"
                  width="170"
                />
                <el-table-column
                  prop="asserted_result"
                  label="声称结果"
                  width="120"
                />
                <el-table-column
                  prop="created_at"
                  label="时间"
                  width="180"
                />
              </el-table>
            </el-tab-pane>
          </el-tabs>
        </el-col>
        <el-col :span="7">
          <el-card header="元数据">
            <el-descriptions
              :column="1"
              border
              size="small"
            >
              <el-descriptions-item label="organization">
                {{ store.detail.organization_id }}
              </el-descriptions-item>
              <el-descriptions-item label="owner_team">
                {{ store.detail.owner_team }}
              </el-descriptions-item>
              <el-descriptions-item label="assignee">
                {{ store.detail.assignee ?? '—' }}
              </el-descriptions-item>
              <el-descriptions-item label="policy_version">
                {{ store.detail.policy_version ?? '—' }}
              </el-descriptions-item>
              <el-descriptions-item label="closure_reason">
                {{ store.detail.closure_reason ?? '—' }}
              </el-descriptions-item>
              <el-descriptions-item label="created_at">
                {{ store.detail.created_at }}
              </el-descriptions-item>
              <el-descriptions-item label="updated_at">
                {{ store.detail.updated_at }}
              </el-descriptions-item>
              <el-descriptions-item label="version">
                v{{ store.detail.version }}
              </el-descriptions-item>
            </el-descriptions>
          </el-card>
        </el-col>
      </el-row>

      <VerificationDrawer v-model="verifyVisible" />
    </template>
    <el-result
      v-else-if="loadError"
      icon="warning"
      title="无法加载工单"
      :sub-title="loadError"
    >
      <template #extra>
        <el-button
          type="primary"
          @click="router.back()"
        >
          返回列表
        </el-button>
        <el-button @click="retry">
          重试
        </el-button>
      </template>
    </el-result>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElButton, ElResult } from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'
import StatusStepper from '../components/StatusStepper.vue'
import CaseActionBar from '../components/CaseActionBar.vue'
import VerificationDrawer from '../components/VerificationDrawer.vue'
import PriorityTag from '../components/PriorityTag.vue'
import SlaBadge from '../components/SlaBadge.vue'

const route = useRoute()
const router = useRouter()
const store = useCaseDetailStore()
const tab = ref('exposures')
const verifyVisible = ref(false)
const loadError = ref('')

const exposureRows = computed(() =>
  (store.detail?.exposures ?? []).map((id: string) => ({ id })),
)

let timer: number | undefined
onMounted(async () => {
  try {
    await store.fetchAll(route.params.id as string)
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : '加载失败'
  }
  timer = window.setInterval(() => {
    if (document.visibilityState === 'visible' && !store.loading) {
      store.refresh().catch(() => {}) // 轮询失败静默，保留上次数据
    }
  }, 15_000)
})
onBeforeUnmount(() => window.clearInterval(timer))

async function retry() {
  loadError.value = ''
  try {
    await store.fetchAll(route.params.id as string)
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : '加载失败'
  }
}
</script>

<style scoped>
.detail-header { margin-bottom: 18px; }
.case-key { font-weight: 700; margin-right: 10px; }
.case-title { margin-right: 10px; }
.detail-body { margin-top: 22px; }
</style>

<template>
  <el-card header="提交 SBOM（CycloneDX / SPDX）">
    <el-input
      v-model="text"
      type="textarea"
      :rows="12"
      placeholder="粘贴 CycloneDX 或 SPDX JSON，例如 {&quot;bomFormat&quot;:&quot;CycloneDX&quot;,&quot;specVersion&quot;:&quot;1.5&quot;,&quot;components&quot;:[…]}"
    />
    <div class="actions">
      <el-upload
        :auto-upload="false"
        :show-file-list="false"
        :on-change="onFile"
      >
        <el-button>从文件读取</el-button>
      </el-upload>
      <el-button
        type="primary"
        class="submit-btn"
        :loading="submitting"
        @click="submit"
      >
        提交
      </el-button>
    </div>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      class="result"
    />
    <el-descriptions
      v-if="result"
      :column="1"
      border
      class="result"
      title="摄取结果"
    >
      <el-descriptions-item label="sbom_id">
        {{ result.sbom_id }}
      </el-descriptions-item>
      <el-descriptions-item label="content_sha256">
        {{ result.content_sha256 }}
      </el-descriptions-item>
      <el-descriptions-item label="status">
        {{ result.status }}
      </el-descriptions-item>
    </el-descriptions>
  </el-card>

  <el-card
    header="本地提交历史"
    class="history"
  >
    <el-table
      :data="history"
      size="small"
    >
      <el-table-column
        prop="at"
        label="时间"
        width="200"
      />
      <el-table-column
        prop="org"
        label="组织"
        width="140"
      />
      <el-table-column
        prop="sbom_id"
        label="SBOM ID"
      />
      <el-table-column
        prop="sha"
        label="SHA-256"
        show-overflow-tooltip
      />
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import {
  ElAlert,
  ElButton,
  ElCard,
  ElDescriptions,
  ElDescriptionsItem,
  ElInput,
  ElMessage,
  ElTable,
  ElTableColumn,
  ElUpload,
} from 'element-plus'
import type { UploadFile } from 'element-plus'
import { apiClient, ApiError } from '../api/client'
import { useOrgStore } from '../stores/org'
import { useSbomHistoryStore } from '../stores/sbomHistory'
import { storeToRefs } from 'pinia'

const text = ref('')
const submitting = ref(false)
const error = ref('')
const result = ref<Record<string, string> | null>(null)
const orgStore = useOrgStore()
const historyStore = useSbomHistoryStore()
const { history } = storeToRefs(historyStore)

watch(
  () => historyStore.generation,
  () => {
    text.value = ''
    submitting.value = false
    error.value = ''
    result.value = null
  },
)

function onFile(file: UploadFile) {
  file.raw?.text().then((t) => (text.value = t))
}

async function submit() {
  error.value = ''
  result.value = null
  let payload: unknown
  try {
    payload = JSON.parse(text.value)
  } catch {
    error.value = '输入不是合法的 JSON'
    return
  }
  submitting.value = true
  const org = orgStore.org
  const requestGeneration = historyStore.generation
  try {
    const key =
      globalThis.crypto?.randomUUID?.() ??
      `sbom-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const resp = await apiClient.submitSbom(org, payload, key)
    const submittedResult = {
      sbom_id: String(resp.sbom_id ?? ''),
      content_sha256: String(resp.content_sha256 ?? ''),
      status: String(resp.status ?? ''),
    }
    const recorded = historyStore.record(
      {
        at: new Date().toLocaleString(),
        org,
        sbom_id: submittedResult.sbom_id,
        sha: submittedResult.content_sha256,
      },
      requestGeneration,
    )
    if (!recorded) return
    result.value = submittedResult
    ElMessage.success('SBOM 已接受')
  } catch (err) {
    if (requestGeneration !== historyStore.generation) return
    error.value = err instanceof ApiError ? `后端拒绝（${err.status}）：${err.message}` : '提交失败'
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.actions { margin-top: 12px; display: flex; gap: 12px; }
.result { margin-top: 16px; }
.history { margin-top: 16px; }
</style>

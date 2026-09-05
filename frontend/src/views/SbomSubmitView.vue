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
import { onMounted, ref } from 'vue'
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

const HISTORY_KEY = 'vulnops.sbom-history'

const text = ref('')
const submitting = ref(false)
const error = ref('')
const result = ref<Record<string, string> | null>(null)
const history = ref<Array<{ at: string; org: string; sbom_id: string; sha: string }>>([])

function loadHistory() {
  history.value = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]')
}

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
  try {
    const key =
      globalThis.crypto?.randomUUID?.() ??
      `sbom-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const resp = await apiClient.submitSbom(useOrgStore().org, payload, key)
    result.value = {
      sbom_id: String(resp.sbom_id ?? ''),
      content_sha256: String(resp.content_sha256 ?? ''),
      status: String(resp.status ?? ''),
    }
    history.value = [
      {
        at: new Date().toLocaleString(),
        org: useOrgStore().org,
        sbom_id: result.value.sbom_id,
        sha: result.value.content_sha256,
      },
      ...history.value,
    ].slice(0, 20)
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.value))
    ElMessage.success('SBOM 已接受')
  } catch (err) {
    error.value = err instanceof ApiError ? `后端拒绝（${err.status}）：${err.message}` : '提交失败'
  } finally {
    submitting.value = false
  }
}

onMounted(loadHistory)
</script>

<style scoped>
.actions { margin-top: 12px; display: flex; gap: 12px; }
.result { margin-top: 16px; }
.history { margin-top: 16px; }
</style>

<template>
  <el-drawer
    v-model="visible"
    title="提交复测证据"
    size="420px"
  >
    <el-form label-width="110px">
      <el-form-item label="复测方式">
        <el-select v-model="form.method">
          <el-option
            label="扫描器复测"
            value="scanner"
          />
          <el-option
            label="Wazuh 主机清单"
            value="wazuh_inventory"
          />
          <el-option
            label="人工确认"
            value="manual_attestation"
          />
        </el-select>
      </el-form-item>
      <el-form-item label="覆盖结果">
        <el-select v-model="form.coverage.status">
          <el-option
            label="完整 (complete)"
            value="complete"
          />
          <el-option
            label="部分 (partial)"
            value="partial"
          />
          <el-option
            label="失败 (failed)"
            value="failed"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        v-if="form.method === 'scanner'"
        label="范围版本"
      >
        <el-input
          v-model="form.coverage.scope_version"
          placeholder="如 v2（复测扫描的范围标识）"
        />
      </el-form-item>
      <el-form-item label="证据 ID">
        <el-input
          v-model="evidenceText"
          placeholder="逗号分隔"
        />
      </el-form-item>
      <el-form-item>
        <el-button
          type="primary"
          :loading="submitting"
          @click="submit"
        >
          提交复测
        </el-button>
      </el-form-item>
      <el-alert
        title="partial / failed / 过期证据永远不会关闭工单（never close on missing data）"
        type="info"
        :closable="false"
      />
    </el-form>
  </el-drawer>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import {
  ElAlert,
  ElButton,
  ElDrawer,
  ElForm,
  ElFormItem,
  ElInput,
  ElMessage,
  ElOption,
  ElSelect,
} from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'

const visible = defineModel<boolean>({ default: false })
const store = useCaseDetailStore()
const submitting = ref(false)
const evidenceText = ref('')

const form = reactive({
  method: 'scanner',
  coverage: { status: 'complete', scope_version: '' },
})

async function submit() {
  submitting.value = true
  try {
    const coverage: Record<string, unknown> = { status: form.coverage.status }
    if (form.method === 'scanner' && form.coverage.scope_version) {
      coverage.scope_version = form.coverage.scope_version
    }
    const resp = await store.verify({
      method: form.method,
      coverage,
      evidence_ids: evidenceText.value.split(',').map((s) => s.trim()).filter(Boolean),
    })
    if (resp?.status === 'closed') {
      ElMessage.success('复测通过，工单已关闭')
    } else if (resp?.status === 'insufficient_evidence') {
      ElMessage.warning('证据不足，工单未关闭（partial/failed/过期证据不能证明整改）')
    } else {
      ElMessage.warning('复测已记录，需人工审批后关闭')
    }
    visible.value = false
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '提交失败')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-drawer
    v-model="visible"
    :title="title"
    size="420px"
  >
    <el-form label-width="90px">
      <el-form-item label="类型">
        <el-select
          v-model="form.type"
          :disabled="mode === 'not_applicable'"
        >
          <el-option
            label="风险接受"
            value="risk_accepted"
          />
          <el-option
            label="误报"
            value="false_positive"
          />
          <el-option
            label="不受影响"
            value="not_affected"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        label="原因"
        required
      >
        <el-input
          v-model="form.reason"
          type="textarea"
          :rows="3"
        />
      </el-form-item>
      <el-form-item label="证据 ID">
        <el-input
          v-model="evidenceText"
          placeholder="逗号分隔，如 ev-1,ev-2"
        />
      </el-form-item>
      <el-form-item label="失效时间">
        <el-date-picker
          v-model="form.expires_at"
          type="datetime"
          value-format="YYYY-MM-DDTHH:mm:ssZ"
        />
      </el-form-item>
      <el-form-item>
        <el-button
          type="primary"
          :loading="submitting"
          @click="submit"
        >
          提交决策
        </el-button>
      </el-form-item>
    </el-form>
  </el-drawer>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import {
  ElButton,
  ElDatePicker,
  ElDrawer,
  ElForm,
  ElFormItem,
  ElInput,
  ElMessage,
  ElOption,
  ElSelect,
} from 'element-plus'
import { useCaseDetailStore } from '../stores/caseDetail'
import type { RiskDecisionRequest } from '../api/types'

const props = defineProps<{ mode: 'risk_accepted' | 'not_applicable' }>()
const visible = defineModel<boolean>({ default: false })

const store = useCaseDetailStore()
const submitting = ref(false)

const title = computed(() => (props.mode === 'not_applicable' ? '标记不适用' : '风险接受申请'))

const form = reactive<Pick<RiskDecisionRequest, 'type' | 'reason' | 'expires_at'> & { type: NonNullable<RiskDecisionRequest['type']> }>({
  type: 'risk_accepted',
  reason: '',
  expires_at: '',
})
const evidenceText = ref('')

watch(visible, (v) => {
  if (v && props.mode === 'not_applicable') form.type = 'not_affected'
  if (v && props.mode === 'risk_accepted') form.type = 'risk_accepted'
})

async function submit() {
  if (!form.reason.trim() || !form.expires_at) {
    ElMessage.warning('原因和失效时间为必填')
    return
  }
  submitting.value = true
  try {
    const resp = await store.decide({
      type: form.type,
      reason: form.reason,
      evidence_ids: evidenceText.value.split(',').map((s) => s.trim()).filter(Boolean),
      expires_at: form.expires_at,
    })
    if (resp) ElMessage.success('决策申请已提交，等待独立审批')
    visible.value = false
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '提交失败')
  } finally {
    submitting.value = false
  }
}
</script>

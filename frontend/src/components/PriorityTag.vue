<template>
  <el-tag
    :type="type"
    effect="dark"
    size="small"
  >
    {{ priority }}
  </el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ priority: string }>()
const type = computed(() => {
  if (props.priority === 'P0' || props.priority === 'P1') return 'danger'
  if (props.priority === 'P2') return 'warning'
  return 'info'
})
</script>

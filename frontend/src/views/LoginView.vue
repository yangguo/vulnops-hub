<template>
  <main class="login-page">
    <el-card class="login-card">
      <div class="login-brand">
        🛡 VulnOps Hub
      </div>
      <h1>{{ isCallback ? '正在完成登录' : '登录控制台' }}</h1>
      <p class="login-copy">
        {{ isCallback ? '正在验证身份，请稍候…' : '使用组织身份提供商登录以访问安全运营数据。' }}
      </p>
      <el-alert
        v-if="errorMessage"
        :title="errorMessage"
        type="error"
        :closable="false"
        class="login-alert"
      />
      <el-button
        v-if="!isCallback"
        type="primary"
        size="large"
        :loading="loading"
        class="login-button"
        @click="startLogin"
      >
        使用企业账号登录
      </el-button>
      <el-button
        v-else-if="errorMessage"
        type="primary"
        class="login-button"
        @click="router.replace({ name: 'login' })"
      >
        返回登录
      </el-button>
    </el-card>
  </main>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElAlert, ElButton, ElCard } from 'element-plus'
import { useAuthStore } from '../stores/auth'
import { safeReturnTo } from '../auth/safeReturnTo'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const loading = ref(false)
const errorMessage = ref('')
const isCallback = computed(() => route.path === '/auth/callback')

async function startLogin() {
  loading.value = true
  errorMessage.value = ''
  try {
    await auth.login(safeReturnTo(route.query.redirect))
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '无法启动登录，请重试'
  } finally {
    loading.value = false
  }
}

async function completeLogin() {
  loading.value = true
  errorMessage.value = ''
  try {
    const returnTo = await auth.handleCallback()
    await router.replace(safeReturnTo(returnTo))
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : auth.error || '登录失败，请重试'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  if (isCallback.value) void completeLogin()
})
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
  box-sizing: border-box;
  background: #f5f7fa;
}

.login-card { width: min(420px, 100%); }
.login-brand { font-weight: 700; font-size: 18px; margin-bottom: 28px; }
h1 { margin: 0 0 10px; font-size: 24px; }
.login-copy { color: var(--el-text-color-secondary); line-height: 1.6; margin: 0 0 24px; }
.login-alert { margin-bottom: 16px; }
.login-button { width: 100%; }
</style>

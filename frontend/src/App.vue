<template>
  <el-container class="app-shell">
    <el-aside
      width="220px"
      class="app-aside"
    >
      <div class="app-logo">
        🛡 VulnOps Hub
      </div>
      <el-menu
        router
        :default-active="route.path"
        class="app-menu"
      >
        <el-menu-item index="/">
          📊 看板
        </el-menu-item>
        <el-menu-item index="/cases">
          📋 工单
        </el-menu-item>
        <el-menu-item index="/sboms">
          📦 SBOM 提交
        </el-menu-item>
        <el-menu-item-group title="未来模块">
          <el-menu-item
            index="/assets"
            disabled
          >
            🏷 资产
          </el-menu-item>
          <el-menu-item
            index="/intel"
            disabled
          >
            🛰 情报
          </el-menu-item>
        </el-menu-item-group>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="app-header">
        <span class="app-title">{{ pageTitle }}</span>
        <div class="header-right">
          <el-select
            :model-value="orgStore.org"
            filterable
            allow-create
            default-first-option
            placeholder="组织"
            style="width: 160px"
            @change="switchOrg"
          >
            <el-option
              label="org-demo"
              value="org-demo"
            />
          </el-select>
          <span class="app-env">内网评估版 · 未启用认证</span>
        </div>
      </el-header>
      <el-main><router-view /></el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useOrgStore } from './stores/org'

const route = useRoute()
const orgStore = useOrgStore()
const pageTitle = computed(() => {
  if (route.path === '/') return '看板'
  if (route.path.startsWith('/cases/')) return '工单详情'
  if (route.path === '/cases') return '整改工单'
  if (route.path === '/sboms') return 'SBOM 提交'
  return 'VulnOps Hub'
})

function switchOrg(org: string) {
  orgStore.setOrg(org)
  window.location.reload() // MVP: 切换组织后整页刷新，重取所有数据
}
</script>

<style>
body { margin: 0; font-family: system-ui, sans-serif; }
.app-shell { height: 100vh; }
.app-aside { border-right: 1px solid var(--el-border-color-light); }
.app-logo { font-weight: 700; font-size: 16px; padding: 18px 20px; }
.app-menu { border-right: none; }
.app-header {
  display: flex; align-items: center; justify-content: space-between;
  border-bottom: 1px solid var(--el-border-color-light);
}
.header-right { display: flex; align-items: center; gap: 12px; }
.app-title { font-size: 16px; font-weight: 600; }
.app-env { color: var(--el-color-warning); font-size: 12px; }
</style>

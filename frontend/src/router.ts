import { createRouter, createWebHistory } from 'vue-router'
import { getActivePinia } from 'pinia'
import { configureApiClient } from './api/client'
import { useAuthStore } from './stores/auth'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('./views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/auth/callback',
      name: 'oidc-callback',
      component: () => import('./views/LoginView.vue'),
      meta: { public: true },
    },
    { path: '/', name: 'dashboard', component: () => import('./views/DashboardView.vue') },
    { path: '/cases', name: 'cases', component: () => import('./views/CaseListView.vue') },
    { path: '/cases/:id', name: 'case-detail', component: () => import('./views/CaseDetailView.vue') },
    {
      path: '/sboms',
      name: 'sboms',
      component: () => import('./views/SbomSubmitView.vue'),
      meta: { capability: 'sbom:write' },
    },
    { path: '/source-health', name: 'source-health', component: () => import('./views/SourceHealthView.vue') },
    {
      path: '/review',
      name: 'candidate-review',
      component: () => import('./views/CandidateReviewView.vue'),
      meta: { capability: 'risk:request' },
    },
  ],
})

function currentAuthStore() {
  const pinia = getActivePinia()
  return pinia ? useAuthStore(pinia) : null
}

configureApiClient({
  getAccessToken: () => currentAuthStore()?.accessToken ?? null,
  onUnauthorized: () => {
    const auth = currentAuthStore()
    if (!auth) return
    auth.handleUnauthorized()
    if (router.currentRoute.value.name !== 'login') {
      void router.push({
        name: 'login',
        query: { redirect: router.currentRoute.value.fullPath },
      })
    }
  },
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const auth = currentAuthStore()
  if (!auth || !(await auth.initialize())) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (typeof to.meta.capability === 'string' && !auth.hasCapability(to.meta.capability)) {
    return { name: 'dashboard' }
  }
  return true
})

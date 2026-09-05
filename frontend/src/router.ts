import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: () => import('./views/DashboardView.vue') },
    { path: '/cases', component: () => import('./views/CaseListView.vue') },
    { path: '/cases/:id', component: () => import('./views/CaseDetailView.vue') },
    { path: '/sboms', component: () => import('./views/SbomSubmitView.vue') },
  ],
})

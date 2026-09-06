import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import ElementPlus from 'element-plus'
import App from './App.vue'

const authDouble = vi.hoisted(() => ({
  displayName: 'User A',
  subject: 'user-a',
  roles: ['owner'],
  hasCapability: vi.fn(() => true),
  logout: vi.fn(),
}))

const orgDouble = vi.hoisted(() => ({
  org: 'org-demo',
  setOrg: vi.fn(),
}))

vi.mock('./stores/auth', () => ({ useAuthStore: () => authDouble }))
vi.mock('./stores/org', () => ({ useOrgStore: () => orgDouble }))

describe('App logout fallback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authDouble.logout.mockRejectedValue(new Error('provider unavailable'))
  })

  it('routes to login when provider logout rejects after local cleanup', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/cases', name: 'cases', component: { template: '<div>cases</div>' } },
        { path: '/login', name: 'login', component: { template: '<div>login</div>' } },
      ],
    })
    await router.push('/cases')
    await router.isReady()
    const wrapper = mount(App, { global: { plugins: [router, ElementPlus] } })

    await wrapper.get('.header-right button').trigger('click')
    await flushPromises()

    expect(authDouble.logout).toHaveBeenCalledWith()
    expect(router.currentRoute.value.name).toBe('login')
  })
})

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import LoginView from './LoginView.vue'

const authDouble = vi.hoisted(() => ({
  error: '',
  isAuthenticated: false,
  loading: false,
  login: vi.fn(),
  handleCallback: vi.fn(),
}))

vi.mock('../stores/auth', () => ({
  useAuthStore: () => authDouble,
}))

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/login', component: LoginView },
      { path: '/auth/callback', component: LoginView },
      { path: '/cases/:id', component: { template: '<div>case</div>' } },
    ],
  })
}

async function mountAt(path: string) {
  const router = makeRouter()
  await router.push(path)
  await router.isReady()
  const wrapper = mount(LoginView, { global: { plugins: [router] } })
  await flushPromises()
  return { router, wrapper }
}

describe('LoginView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    authDouble.error = ''
    authDouble.isAuthenticated = false
    authDouble.loading = false
    authDouble.login.mockResolvedValue(undefined)
    authDouble.handleCallback.mockResolvedValue('/cases/c1')
  })

  it('starts login with the guarded redirect path from the query string', async () => {
    const { wrapper } = await mountAt('/login?redirect=%2Fcases%2Fc1')

    await wrapper.get('button.el-button').trigger('click')

    expect(authDouble.login).toHaveBeenCalledWith('/cases/c1')
  })

  it('handles the authorization callback and returns to the requested route', async () => {
    const { router } = await mountAt('/auth/callback?code=code-1&state=state-1')

    expect(authDouble.handleCallback).toHaveBeenCalledWith()
    expect(router.currentRoute.value.fullPath).toBe('/cases/c1')
  })
})

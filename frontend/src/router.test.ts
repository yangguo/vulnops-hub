import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises } from '@vue/test-utils'
import { apiClient } from './api/client'
import { router } from './router'

const authDouble = vi.hoisted(() => ({
  accessToken: null as string | null,
  isAuthenticated: false,
  initialize: vi.fn(),
  hasCapability: vi.fn(),
  handleUnauthorized: vi.fn(),
}))

vi.mock('./stores/auth', () => ({
  useAuthStore: () => authDouble,
}))

describe('authenticated router boundary', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    authDouble.accessToken = null
    authDouble.isAuthenticated = false
    authDouble.initialize.mockResolvedValue(false)
    authDouble.hasCapability.mockReturnValue(false)
    authDouble.handleUnauthorized.mockImplementation(() => {
      authDouble.accessToken = null
      authDouble.isAuthenticated = false
    })
    await router.push('/login')
  })

  it('redirects unauthenticated protected routes to login with the original path', async () => {
    await router.push('/cases')

    expect(authDouble.initialize).toHaveBeenCalledWith()
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.redirect).toBe('/cases')
  })

  it('allows an authenticated route and injects the current auth-store token', async () => {
    authDouble.isAuthenticated = true
    authDouble.accessToken = 'access-token'
    authDouble.initialize.mockResolvedValue(true)
    await router.push('/cases')

    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    await apiClient.getCase('org-demo', 'case-1')

    expect(router.currentRoute.value.path).toBe('/cases')
    expect(new Headers(fetchMock.mock.calls[0][1].headers).get('authorization')).toBe(
      'Bearer access-token',
    )
  })

  it('redirects away from mutation routes without the required capability', async () => {
    authDouble.isAuthenticated = true
    authDouble.initialize.mockResolvedValue(true)
    authDouble.hasCapability.mockReturnValue(false)

    await router.push('/sboms')

    expect(authDouble.hasCapability).toHaveBeenCalledWith('sbom:write')
    expect(router.currentRoute.value.name).toBe('dashboard')
  })

  it('clears auth and redirects to login after an API 401', async () => {
    authDouble.isAuthenticated = true
    authDouble.accessToken = 'expired-token'
    authDouble.initialize.mockResolvedValue(true)
    await router.push('/cases')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ code: 'invalid_token' }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    )

    await expect(apiClient.getCase('org-demo', 'case-1')).rejects.toMatchObject({ status: 401 })
    await flushPromises()

    expect(authDouble.handleUnauthorized).toHaveBeenCalledWith()
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.redirect).toBe('/cases')
  })
})

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from './auth'

const oidcDoubles = vi.hoisted(() => {
  const callbacks: {
    accessTokenExpired?: () => void | Promise<void>
    userLoaded?: (user: unknown) => void | Promise<void>
    userUnloaded?: () => void | Promise<void>
  } = {}

  const events = {
    addAccessTokenExpired: vi.fn((callback: () => void | Promise<void>) => {
      callbacks.accessTokenExpired = callback
      return () => undefined
    }),
    addUserLoaded: vi.fn((callback: (user: unknown) => void | Promise<void>) => {
      callbacks.userLoaded = callback
      return () => undefined
    }),
    addUserUnloaded: vi.fn((callback: () => void | Promise<void>) => {
      callbacks.userUnloaded = callback
      return () => undefined
    }),
  }

  const manager = {
    events,
    getUser: vi.fn(),
    signinRedirect: vi.fn(),
    signinCallback: vi.fn(),
    signoutRedirect: vi.fn(),
    removeUser: vi.fn(),
  }

  return { callbacks, manager }
})

vi.mock('../auth/oidc', () => ({
  oidcUserManager: oidcDoubles.manager,
}))

function makeUser(overrides: Record<string, unknown> = {}) {
  return {
    access_token: 'access-token',
    refresh_token: 'refresh-token',
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    expired: false,
    state: { returnTo: '/cases/c1' },
    scope: 'openid profile email',
    profile: {
      sub: 'user-1',
      name: 'Ada Lovelace',
      email: 'ada@example.test',
      organizations: ['acme'],
      roles: ['owner'],
      principal_type: 'human',
    },
    ...overrides,
  }
}

describe('auth store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    oidcDoubles.manager.getUser.mockResolvedValue(null)
    oidcDoubles.manager.signinRedirect.mockResolvedValue(undefined)
    oidcDoubles.manager.signinCallback.mockResolvedValue(makeUser())
    oidcDoubles.manager.signoutRedirect.mockResolvedValue(undefined)
    oidcDoubles.manager.removeUser.mockResolvedValue(undefined)
    delete oidcDoubles.callbacks.accessTokenExpired
    delete oidcDoubles.callbacks.userLoaded
    delete oidcDoubles.callbacks.userUnloaded
  })

  it('starts login with a redirect state containing the requested path', async () => {
    const store = useAuthStore()

    await store.login('/cases/c1')

    expect(oidcDoubles.manager.signinRedirect).toHaveBeenCalledWith({
      state: { returnTo: '/cases/c1' },
    })
  })

  it('loads the callback user and derives owner capabilities in memory', async () => {
    const store = useAuthStore()

    const returnTo = await store.handleCallback()

    expect(returnTo).toBe('/cases/c1')
    expect(store.isAuthenticated).toBe(true)
    expect(store.accessToken).toBe('access-token')
    expect(store.roles).toEqual(['owner'])
    expect(store.organizations).toEqual(['acme'])
    expect(store.hasCapability('case:read')).toBe(true)
    expect(store.hasCapability('case:write')).toBe(true)
    expect(store.hasCapability('risk:request')).toBe(true)
    expect(store.hasCapability('verification:write')).toBe(true)
  })

  it('clears the session before redirecting to provider logout', async () => {
    const store = useAuthStore()
    await store.handleCallback()

    await store.logout()

    expect(oidcDoubles.manager.signoutRedirect).toHaveBeenCalledWith()
    expect(store.user).toBeNull()
    expect(store.accessToken).toBeNull()
    expect(store.isAuthenticated).toBe(false)
  })

  it('removes an expired user during initialization', async () => {
    oidcDoubles.manager.getUser.mockResolvedValueOnce(
      makeUser({ expires_at: Math.floor(Date.now() / 1000) - 1, expired: true }),
    )
    const store = useAuthStore()

    await store.initialize()

    expect(oidcDoubles.manager.removeUser).toHaveBeenCalledWith()
    expect(store.isAuthenticated).toBe(false)
  })

  it('clears the session when the OIDC access-token expiry event fires', async () => {
    const store = useAuthStore()
    await store.initialize()
    await oidcDoubles.callbacks.accessTokenExpired?.()

    expect(oidcDoubles.manager.removeUser).toHaveBeenCalledWith()
    expect(store.isAuthenticated).toBe(false)
  })

  it('limits service capabilities to named scopes, not human permissions', async () => {
    oidcDoubles.manager.signinCallback.mockResolvedValueOnce(
      makeUser({
        profile: {
          sub: 'service-1',
          principal_type: 'service',
          permissions: ['case:write'],
        },
        scope: 'sbom:write',
      }),
    )
    const store = useAuthStore()

    await store.handleCallback()

    expect(store.hasCapability('case:write')).toBe(false)
    expect(store.hasCapability('sbom:write')).toBe(true)
  })
})

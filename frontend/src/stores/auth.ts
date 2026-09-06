import { defineStore } from 'pinia'
import type { User } from 'oidc-client-ts'
import { oidcUserManager } from '../auth/oidc'
import { returnToFromState } from '../auth/safeReturnTo'
import { clearUserBoundBrowserState } from '../auth/sessionCleanup'

const ROLE_CAPABILITIES: Record<string, readonly string[]> = {
  viewer: ['case:read', 'sbom:read'],
  owner: ['case:write', 'risk:request', 'verification:write'],
  auditor: ['audit:read', 'case:read', 'provenance:read', 'risk:read', 'verification:read'],
  risk_approver: ['risk:approve'],
  security_lead: [],
  admin: ['case:write', 'risk:approve', 'risk:request', 'sbom:write', 'verification:write'],
}

const SERVICE_SCOPE_CAPABILITIES = new Set([
  'evidence:raw:read',
  'evidence:write',
  'sbom:read',
  'sbom:write',
])

const HUMAN_ROLE_CAPABILITIES = new Set([
  ...Object.values(ROLE_CAPABILITIES).flat(),
  'case:read',
  'sbom:read',
  'audit:read',
  'provenance:read',
  'risk:read',
  'verification:read',
])

type ClaimValue = unknown
const runtimeEnvironment = import.meta.env as Record<string, string | undefined>
const ORGANIZATION_CLAIM = runtimeEnvironment.VITE_OIDC_ORGANIZATION_CLAIM || 'organizations'
const ROLE_CLAIM = runtimeEnvironment.VITE_OIDC_ROLE_CLAIM || 'roles'
const PRINCIPAL_TYPE_CLAIM = runtimeEnvironment.VITE_OIDC_PRINCIPAL_TYPE_CLAIM || 'principal_type'
const PERMISSION_CLAIM = runtimeEnvironment.VITE_OIDC_PERMISSION_CLAIM || 'permissions'

function profileClaim(user: User | null, claimName: string): ClaimValue {
  return user?.profile?.[claimName]
}

function claimValues(value: ClaimValue): string[] {
  if (typeof value === 'string') return value.split(/\s+/).map((item) => item.trim()).filter(Boolean)
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter(Boolean)
}

function normalizedRoles(user: User | null): string[] {
  const roles = claimValues(profileClaim(user, ROLE_CLAIM)).map((role) => role.toLowerCase().replaceAll('-', '_'))
  return [...new Set(roles)].sort()
}

function normalizedOrganizations(user: User | null): string[] {
  return [...new Set(claimValues(profileClaim(user, ORGANIZATION_CLAIM)))].sort()
}

function normalizedScopes(user: User | null): string[] {
  const profileScope = claimValues(user?.profile?.scope)
  const userScope = claimValues(user?.scope)
  return [...new Set([...profileScope, ...userScope].map((scope) => scope.toLowerCase()))].sort()
}

function normalizedPermissions(user: User | null): string[] {
  return [...new Set(claimValues(profileClaim(user, PERMISSION_CLAIM)).map((permission) => permission.toLowerCase()))].sort()
}

function capabilitiesForUser(user: User | null): string[] {
  if (!user) return []

  const roles = normalizedRoles(user)
  const principalTypeClaim = profileClaim(user, PRINCIPAL_TYPE_CLAIM)
  const principalType = typeof principalTypeClaim === 'string'
    ? principalTypeClaim.toLowerCase()
    : 'human'

  if (principalType === 'service') {
    const capabilities = new Set<string>()
    for (const scope of normalizedScopes(user)) {
      if (SERVICE_SCOPE_CAPABILITIES.has(scope)) capabilities.add(scope)
    }
    return [...capabilities].sort()
  }

  const capabilities = new Set<string>(normalizedPermissions(user))
  for (const role of roles) {
    for (const capability of ROLE_CAPABILITIES[role] ?? []) capabilities.add(capability)
  }
  if (roles.some((role) => ['owner', 'risk_approver', 'security_lead', 'admin'].includes(role))) {
    capabilities.add('case:read')
    capabilities.add('sbom:read')
  }
  if (roles.some((role) => ['risk_approver', 'security_lead', 'admin'].includes(role))) {
    capabilities.add('risk:approve')
  }
  if (roles.includes('security_lead')) {
    for (const capability of ROLE_CAPABILITIES.owner) capabilities.add(capability)
  }
  if (roles.includes('admin')) {
    for (const capability of HUMAN_ROLE_CAPABILITIES) capabilities.add(capability)
  }
  return [...capabilities].sort()
}

function isExpired(user: User | null): boolean {
  if (!user) return false
  if (user.expired === true) return true
  return typeof user.expires_at === 'number' && user.expires_at <= Math.floor(Date.now() / 1000)
}


export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null as User | null,
    loading: false,
    initialized: false,
    error: '',
    eventsBound: false,
  }),
  getters: {
    isAuthenticated: (state) => state.user !== null && !isExpired(state.user),
    accessToken: (state) => (state.user && !isExpired(state.user) ? state.user.access_token : null),
    subject: (state) => (typeof state.user?.profile?.sub === 'string' ? state.user.profile.sub : ''),
    displayName: (state) => {
      const profile = state.user?.profile
      return typeof profile?.name === 'string'
        ? profile.name
        : typeof profile?.preferred_username === 'string'
          ? profile.preferred_username
          : typeof profile?.email === 'string'
            ? profile.email
            : ''
    },
    roles: (state) => normalizedRoles(state.user),
    organizations: (state) => normalizedOrganizations(state.user),
    capabilities: (state) => capabilitiesForUser(state.user),
    hasCapability() {
      return (capability: string) => this.capabilities.includes(capability.trim().toLowerCase())
    },
  },
  actions: {
    async initialize(): Promise<boolean> {
      if (this.initialized) return this.isAuthenticated
      this.loading = true
      this.error = ''
      this.bindEvents()
      try {
        const user = await oidcUserManager.getUser()
        if (isExpired(user)) {
          this.user = null
          await oidcUserManager.removeUser()
        } else {
          this.user = user
        }
      } catch {
        this.user = null
        this.error = '无法读取登录状态'
      } finally {
        this.initialized = true
        this.loading = false
      }
      return this.isAuthenticated
    },
    async login(returnTo = '/') {
      this.error = ''
      await oidcUserManager.signinRedirect({
        state: { returnTo },
      })
    },
    async handleCallback(url?: string): Promise<string | null> {
      this.loading = true
      this.error = ''
      this.bindEvents()
      try {
        const user = await oidcUserManager.signinCallback(url)
        if (!user || isExpired(user)) throw new Error('登录令牌已过期')
        this.user = user
        this.initialized = true
        return returnToFromState(user.state)
      } catch (error) {
        this.user = null
        this.error = error instanceof Error ? error.message : '登录失败，请重试'
        throw error
      } finally {
        this.loading = false
      }
    },
    async logout() {
      this.user = null
      this.initialized = true
      this.error = ''
      clearUserBoundBrowserState()
      await oidcUserManager.signoutRedirect()
    },
    handleUnauthorized() {
      this.user = null
      this.initialized = true
      this.error = '登录已失效，请重新登录'
      clearUserBoundBrowserState()
      void oidcUserManager.removeUser().catch(() => undefined)
    },
    bindEvents() {
      if (this.eventsBound) return
      this.eventsBound = true
      oidcUserManager.events.addUserLoaded((user) => {
        this.user = user
        this.error = ''
      })
      oidcUserManager.events.addUserUnloaded(() => {
        this.user = null
      })
      oidcUserManager.events.addAccessTokenExpired(() => {
        this.handleUnauthorized()
      })
    },
  },
})

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { User, WebStorageStateStore } from 'oidc-client-ts'
import { createOidcUserManager, getOidcSettings } from './oidc'

const oidcEnv = {
  VITE_OIDC_AUTHORITY: 'https://idp.example.test/realms/vulnops',
  VITE_OIDC_CLIENT_ID: 'vulnops-console',
  VITE_OIDC_REDIRECT_URI: 'https://console.example.test/auth/callback',
  VITE_OIDC_POST_LOGOUT_REDIRECT_URI: 'https://console.example.test/login',
  VITE_OIDC_SCOPE: 'openid profile email',
}

describe('OIDC configuration', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  it('uses authorization code flow with PKCE and an in-memory user store', () => {
    const settings = getOidcSettings(oidcEnv)

    expect(settings.response_type).toBe('code')
    expect(settings.disablePKCE).not.toBe(true)
    expect(settings.authority).toBe(oidcEnv.VITE_OIDC_AUTHORITY)
    expect(settings.client_id).toBe(oidcEnv.VITE_OIDC_CLIENT_ID)
    expect(settings.redirect_uri).toBe(oidcEnv.VITE_OIDC_REDIRECT_URI)
    expect(settings.userStore).toBeInstanceOf(WebStorageStateStore)
  })

  it('keeps access and refresh tokens out of browser storage', async () => {
    const manager = createOidcUserManager(oidcEnv)
    const user = new User({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      token_type: 'Bearer',
      profile: {
        iss: oidcEnv.VITE_OIDC_AUTHORITY,
        aud: oidcEnv.VITE_OIDC_CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: 'user-1',
      },
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    })

    await manager.storeUser(user)

    await expect(manager.getUser()).resolves.toMatchObject({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
    })
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)

    await manager.removeUser()
  })
})

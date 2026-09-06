import {
  InMemoryWebStorage,
  UserManager,
  WebStorageStateStore,
  type UserManagerSettings,
} from 'oidc-client-ts'

export type OidcEnvironment = Record<string, string | undefined>

const runtimeEnvironment = import.meta.env as OidcEnvironment

function currentOrigin(): string {
  return typeof window === 'undefined' ? '' : window.location.origin
}

/** Build the browser OIDC settings without putting credentials in browser storage. */
export function getOidcSettings(env: OidcEnvironment = runtimeEnvironment): UserManagerSettings {
  const origin = currentOrigin()

  return {
    authority: env.VITE_OIDC_AUTHORITY?.trim() ?? '',
    client_id: env.VITE_OIDC_CLIENT_ID?.trim() ?? '',
    redirect_uri: env.VITE_OIDC_REDIRECT_URI?.trim() || `${origin}/auth/callback`,
    post_logout_redirect_uri:
      env.VITE_OIDC_POST_LOGOUT_REDIRECT_URI?.trim() || `${origin}/login`,
    response_type: 'code',
    scope: env.VITE_OIDC_SCOPE?.trim() || 'openid profile email',
    // The authorization request state must survive the full-page provider redirect;
    // the user (and its access/refresh tokens) must not.
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: false,
    monitorSession: false,
    disablePKCE: false,
  }
}

export function createOidcUserManager(env: OidcEnvironment = runtimeEnvironment): UserManager {
  return new UserManager(getOidcSettings(env))
}

export const oidcUserManager = createOidcUserManager()

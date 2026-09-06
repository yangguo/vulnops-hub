/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OIDC_AUTHORITY?: string
  readonly VITE_OIDC_CLIENT_ID?: string
  readonly VITE_OIDC_REDIRECT_URI?: string
  readonly VITE_OIDC_POST_LOGOUT_REDIRECT_URI?: string
  readonly VITE_OIDC_SCOPE?: string
  readonly VITE_OIDC_ORGANIZATION_CLAIM?: string
  readonly VITE_OIDC_ROLE_CLAIM?: string
  readonly VITE_OIDC_PRINCIPAL_TYPE_CLAIM?: string
  readonly VITE_OIDC_PERMISSION_CLAIM?: string
}

/* eslint-disable @typescript-eslint/no-empty-object-type, @typescript-eslint/no-explicit-any --
   canonical Vite .vue shim; `{}`/`any` are its documented types */
declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

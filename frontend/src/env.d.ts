/// <reference types="vite/client" />

/* eslint-disable @typescript-eslint/no-empty-object-type, @typescript-eslint/no-explicit-any --
   canonical Vite .vue shim; `{}`/`any` are its documented types */
declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

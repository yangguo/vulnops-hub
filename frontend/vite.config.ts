/// <reference types="vitest" />
import { defineConfig } from 'vite'
import { configDefaults } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

const apiTarget = process.env.VITE_API_TARGET || 'http://127.0.0.1:8000'

const proxy = {
  '/api': { target: apiTarget, changeOrigin: true },
  '/health': { target: apiTarget, changeOrigin: true },
  '/docs': { target: apiTarget, changeOrigin: true },
  '/openapi.json': { target: apiTarget, changeOrigin: true },
}

export default defineConfig({
  plugins: [vue()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  // Playwright owns e2e/ — vitest must not collect its specs.
  test: { environment: 'jsdom', globals: true, exclude: [...configDefaults.exclude, 'e2e/**'] },
})

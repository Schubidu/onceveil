import { cloudflare } from '@cloudflare/vite-plugin'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    port: 3000,
  },
  resolve: {
    alias: {
      '#onceveil-runtime-context': fileURLToPath(
        new URL('./src/runtime/cloudflare-request-context.ts', import.meta.url),
      ),
    },
  },
  plugins: [cloudflare({ viteEnvironment: { name: 'ssr' } }), tanstackStart(), react()],
})

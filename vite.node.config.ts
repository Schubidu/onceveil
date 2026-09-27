import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { nitro } from 'nitro/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  resolve: {
    alias: {
      '#onceveil-runtime-context': fileURLToPath(
        new URL('./src/runtime/node-request-context.ts', import.meta.url),
      ),
    },
  },
  plugins: [tanstackStart(), nitro({ preset: 'node-server' }), react()],
})

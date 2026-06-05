import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Builds the dashboard into the Go webui package's embedded dist directory.
// base: './' keeps asset URLs relative so the SPA works under any mount path.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})

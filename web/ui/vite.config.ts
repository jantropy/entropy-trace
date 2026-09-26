import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev-time proxy so the UI can call same-origin `/api/...` without CORS
// setup -- the FastAPI app (web/api) is expected running on :8000 (see
// web/README.md's two-command start).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})

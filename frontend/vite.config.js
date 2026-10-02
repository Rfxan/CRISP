import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const port = Number(process.env.PORT || 5173)
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535')
}

export default defineConfig({
  plugins: [react()],
  server: {
    port,
    // Vercel's gateway routes /api to the backend service. The standalone
    // developer server can optionally proxy to a separately hosted API.
    proxy: process.env.VERCEL ? undefined : {
      '/api': {
        target: process.env.CRISP_API_PROXY_TARGET || 'http://127.0.0.1:8000',
        changeOrigin: true
      }
    }
  }
})

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dashboard talks to the FastAPI backend directly (CORS is open on the
// backend), so no dev proxy is required. VITE_API_BASE_URL is baked in at
// build time; see the Dockerfile for the container build argument.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',
    port: 5173,
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
  },
})

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import legacy from '@vitejs/plugin-legacy'

// The dashboard talks to the FastAPI backend directly (CORS is open on the
// backend), so no dev proxy is required. VITE_API_BASE_URL is baked in at
// build time; see the Dockerfile for the container build argument.
//
// The legacy plugin emits a second ES5 bundle + SystemJS runtime so older
// browsers (Safari 13, older mobile Safari, etc.) can run the dashboard;
// modern browsers ignore it via nomodule and pay no runtime cost.
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    legacy({
      targets: ['safari >= 13', 'ios_saf >= 13', 'chrome >= 64', 'firefox >= 78'],
      modernPolyfills: true,
    }),
  ],
  server: {
    host: '0.0.0.0',
    port: 5173,
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
  },
})

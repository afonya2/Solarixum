import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:1010',
        changeOrigin: true
      },
      '/ws': {
        target: 'ws://localhost:1010',
        ws: true,
        changeOrigin: true
      },
      '/uploads': {
        target: 'http://localhost:1010',
        changeOrigin: true
      }
    }
  }
})

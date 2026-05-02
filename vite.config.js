import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    minify: 'terser',
    target: ['es2020'],
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          msgreader: ['@kenjiuno/msgreader']
        }
      }
    }
  },
  server: {
    port: 5173,
    open: true
  },
  resolve: {
    extensions: ['.js', '.jsx', '.json'],
    alias: {
      buffer: 'buffer'
    }
  },
  define: {
    'process.env': {},
    global: 'globalThis'
  },
  optimizeDeps: {
    include: ['@kenjiuno/msgreader', 'buffer'],
    esbuildOptions: {
      define: {
        global: 'globalThis'
      }
    }
  }
})

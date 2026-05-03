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
    // No manualChunks — let Rollup determine safe split points.
    // Manual chunk splitting across CJS packages causes cross-chunk
    // temporal dead zone crashes (can't access lexical declaration before init).
    rollupOptions: {}
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
    // Force all CJS packages through Vite's pre-bundler together.
    // This ensures their internal circular references are resolved
    // before any ESM module graph wiring happens.
    include: [
      'react',
      'react-dom',
      'react-dom/client',
      '@kenjiuno/msgreader',
      'buffer',
      'dompurify'
    ],
    esbuildOptions: {
      define: {
        global: 'globalThis'
      }
    }
  }
})

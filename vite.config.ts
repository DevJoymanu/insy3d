/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

// Check if SSL certificates exist (for local development)
const certPath = path.resolve(__dirname, '.cert/cert.pem');
const keyPath = path.resolve(__dirname, '.cert/key.pem');
const hasCertificates = fs.existsSync(certPath) && fs.existsSync(keyPath);

// HTTPS configuration (only for local development)
const httpsConfig = hasCertificates
  ? {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  }
  : undefined;

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  server: {
    host: 'localhost',
    port: 5173,
    https: httpsConfig, // Will be undefined in CI/CD
    strictPort: false,
  },

  // Vitest configuration
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: './src/test/setup.ts',
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'src/test/',
        '**/*.test.{ts,tsx}',
        '**/*.spec.{ts,tsx}',
        '**/mockServiceWorker.js',
      ],
    },
  },

  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
});
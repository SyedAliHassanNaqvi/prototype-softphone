import path from 'node:path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

const root = path.resolve(import.meta.dirname, '..');

export default defineConfig(({ mode }) => {
  // Same .env as the gateway, so the dev proxy follows GATEWAY_PORT.
  const env = loadEnv(mode, root, '');
  const gateway = `127.0.0.1:${env.GATEWAY_PORT || 4000}`;
  return {
    root: import.meta.dirname,
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/ws': { target: `ws://${gateway}`, ws: true },
        '/api': { target: `http://${gateway}` },
      },
    },
    build: {
      outDir: path.join(root, 'dist/web'),
      emptyOutDir: true,
    },
  };
});

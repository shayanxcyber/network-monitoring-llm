import {defineConfig} from 'vite';
import {dependencyNotices} from './build-notices.mjs';
export default defineConfig({
  base: '/ui/',
  plugins: [dependencyNotices()],
  build: {outDir: '../web/react', emptyOutDir: true, sourcemap: false, target: 'es2022',
    rolldownOptions: {onwarn(warning, warn) {
      // This is a client-only static bundle; no server-component boundary exists.
      if (warning.code === 'MODULE_LEVEL_DIRECTIVE' && warning.message.includes('use client')) return;
      warn(warning);
    }},
  },
});

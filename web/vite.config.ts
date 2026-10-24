// SPDX-License-Identifier: AGPL-3.0-only

import { mkdirSync, writeFileSync } from 'node:fs';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { defineConfig, type Plugin } from 'vitest/config';

// The Go build embeds web/dist and needs it to be non-empty even before the UI
// is built, so a tracked placeholder must survive the build's clean step.
function keepPlaceholder(): Plugin {
  return {
    name: 'keep-dist-placeholder',
    closeBundle() {
      mkdirSync('dist', { recursive: true });
      writeFileSync('dist/.gitkeep', '');
    },
  };
}

const nuxd = { target: 'https://localhost:8443', secure: false };

export default defineConfig({
  plugins: [svelte(), svelteTesting(), keepPlaceholder()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // The polyfill is an inline script, which the Content Security Policy forbids.
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: { '/api': nuxd, '/healthz': nuxd, '/readyz': nuxd },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
  },
});

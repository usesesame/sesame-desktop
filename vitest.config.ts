import { defineConfig } from 'vitest/config'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { readFileSync } from 'node:fs'

const desktopVersion = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
).version as string

export default defineConfig({
  plugins: [svelte()],
  define: {
    __SESAME_APP_VERSION__: JSON.stringify(desktopVersion),
  },
  resolve: { conditions: ['browser'] },
  test: {
    include: ['src/**/*.test.ts'],
    passWithNoTests: true,
    environment: 'node',
    environmentMatchGlobs: [['src/lib/ui/**/*.test.ts', 'jsdom']],
    restoreMocks: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      include: ['src/lib/**/*.ts', 'src/lib/ui/**/*.svelte'],
      exclude: ['src/**/*.test.ts', 'src/lib/desktop-e2e-bridge.ts'],
    },
  },
})

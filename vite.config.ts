import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { readFileSync } from 'node:fs'

const desktopVersion = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
).version as string

export default defineConfig(() => {
  const syncPreview = process.env.VITE_SESAME_SYNC_PREVIEW === 'true'

  return {
    plugins: [svelte()],
    define: {
      __SESAME_APP_VERSION__: JSON.stringify(desktopVersion),
    },
    cacheDir: syncPreview ? 'node_modules/.vite-sync-preview' : 'node_modules/.vite',
    build: {
      rollupOptions: {
        input: {
          main: 'index.html',
          quickAccess: 'quick-access.html',
        },
      },
    },
  }
})

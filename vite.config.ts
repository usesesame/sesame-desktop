import { defineConfig, type Plugin } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { readFileSync } from 'node:fs'

import { packageNameFromModuleId } from './tools/shipped-packages.mjs'

const desktopVersion = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
).version as string

const shippedNpmPackages = (): Plugin => {
  return {
    name: 'sesame:shipped-npm-packages',
    apply: 'build',
    generateBundle(_options, bundle) {
      const packages = new Set<string>()
      for (const item of Object.values(bundle)) {
        if (item.type !== 'chunk') continue
        for (const id of item.moduleIds) {
          const name = packageNameFromModuleId(id)
          if (name) packages.add(name)
        }
      }
      this.emitFile({
        type: 'asset',
        fileName: 'shipped-npm-packages.json',
        source: `${JSON.stringify([...packages].sort(), null, 2)}\n`,
      })
    },
  }
}

export default defineConfig(() => {
  const syncPreview = process.env.VITE_SESAME_SYNC_PREVIEW === 'true'

  return {
    plugins: [svelte(), shippedNpmPackages()],
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

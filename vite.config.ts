import { defineConfig, type Plugin } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { readFileSync } from 'node:fs'

import { shippedInventory } from './tools/shipped-packages.mjs'

const desktopVersion = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8'),
).version as string

const shippedNpmPackages = (): Plugin => {
  let root = process.cwd()
  return {
    name: 'sesame:shipped-npm-packages',
    apply: 'build',
    configResolved(config) {
      root = config.root
    },
    generateBundle(_options, bundle) {
      const moduleIds: string[] = []
      for (const item of Object.values(bundle)) {
        if (item.type === 'chunk') moduleIds.push(...item.moduleIds)
      }
      this.emitFile({
        type: 'asset',
        fileName: 'shipped-npm-packages.json',
        source: `${JSON.stringify(shippedInventory(moduleIds, root), null, 2)}\n`,
      })
    },
  }
}

export default defineConfig(() => {
  return {
    plugins: [svelte(), shippedNpmPackages()],
    define: {
      __SESAME_APP_VERSION__: JSON.stringify(desktopVersion),
    },
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

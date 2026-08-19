import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

const root = process.cwd()
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

test('website icons load near the viewport through a bounded shared queue', () => {
  const component = read('src', 'lib', 'ui', 'WebsiteIcon.svelte')
  const queue = read('src', 'lib', 'website-icons.ts')
  assert.match(component, /IntersectionObserver/)
  assert.match(component, /rootMargin:\s*'160px'/)
  assert.match(queue, /MAX_CONCURRENT_REQUESTS\s*=\s*4/)
  assert.match(queue, /pendingIcons\.get\(key\)/)
  assert.match(queue, /await waitUntilIdle\(\)[\s\S]*?await clearWebsiteIconCache\(\)/)
})

test('desktop icon requests cannot bypass the native cache', () => {
  const csp = read('src-tauri', 'tauri.conf.json')
  const vaultView = read('src', 'lib', 'ui', 'VaultView.svelte')
  assert.doesNotMatch(csp, /img-src[^;]*https:/)
  assert.doesNotMatch(vaultView, /https:\/\/\$?\{?.*favicon\.ico/)
  assert.match(vaultView, /<WebsiteIcon/)
})

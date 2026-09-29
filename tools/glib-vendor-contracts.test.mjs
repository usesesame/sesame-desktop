import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

test('the vendored glib tree is pinned to a crate digest and a checked-in patch', () => {
  const script = read('tools', 'verify-glib-vendor.mjs')
  assert.match(script, /https:\/\/static\.crates\.io\/crates\/glib\/glib-0\.18\.5\.crate/)
  assert.match(script, /233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5/)
  assert.ok(existsSync(join(root, 'src-tauri', 'vendor', 'glib.patch')), 'the vendor patch is missing')
  const patch = read('src-tauri', 'vendor', 'glib.patch')
  for (const file of ['src/boxed_inline.rs', 'src/lib.rs', 'src/variant_iter.rs']) {
    assert.ok(patch.includes(`a/${file}`), `the patch does not cover ${file}`)
  }
})

test('the supply chain job verifies the vendored tree on every run', () => {
  const workflow = read('.github', 'workflows', 'ci.yml')
  const job = workflow.slice(workflow.indexOf('\n  supply-chain:\n'))
  assert.match(job, /node tools\/verify-glib-vendor\.mjs/, 'the supply chain job does not run the verifier')
})

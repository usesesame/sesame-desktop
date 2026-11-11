import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const sourceRoot = join(root, 'src')
const ignored = new Set(['node_modules', 'dist', '.git'])

function sourceFiles(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name)
    if (statSync(path).isDirectory()) return ignored.has(name) ? [] : sourceFiles(path)
    if (/\.test\.(?:ts|js)$/.test(name) || /\.d\.ts$/.test(name)) return []
    return /\.(?:ts|svelte)$/.test(name) ? [path] : []
  })
}

function source(...parts) {
  return readFileSync(join(sourceRoot, ...parts), 'utf8')
}

test('copy_secret is only reached through the wrapper in vault.ts', () => {
  const callers = sourceFiles(sourceRoot)
    .filter((path) => /copy_secret/.test(readFileSync(path, 'utf8')))
    .map((path) => relative(root, path).replaceAll('\\', '/'))
  assert.deepEqual(callers, ['src/lib/vault.ts'])
})

test('saved secrets copy by reference through the native command', () => {
  assert.match(source('lib', 'vault.ts'), /invoke<number>\('copy_item_field',\s*\{ id, kind, field, clearAfterMs: clipboardClearMs \}\)/)
  const login = source('lib', 'controllers', 'login-controller.ts')
  assert.match(login, /copyItemField\('login', id, 'password'\)/)
  assert.match(login, /copyItemField\('login', id, field\)/)
  assert.match(source('lib', 'controllers', 'item-controller.ts'), /copyItemField\(active\.kind, active\.id, key\)/)
})

test('revealed secrets never feed a clipboard copy', () => {
  const offenders = []
  for (const path of sourceFiles(sourceRoot)) {
    const text = readFileSync(path, 'utf8')
    for (const match of text.matchAll(/copyToClipboard\s*\(\s*(?:await\s+)?(revealLoginSecret|releaseItemField|readPassword)\s*\(/g)) {
      offenders.push(`${relative(root, path)}: ${match[0]}`)
    }
  }
  assert.deepEqual(offenders, [])
})

import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

// Salvaged from the former monorepo workspace suite when the products split.

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const scripts = new Set(Object.keys(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts ?? {}))
const IGNORED = new Set(['node_modules', '.git', 'dist', 'target', 'test-results', 'release-artifacts', 'release-evidence', 'vendor', 'isolated-target', '.phase4-target'])

function filesMatching(pattern, directory = root) {
  const found = []
  for (const entry of readdirSync(directory)) {
    if (IGNORED.has(entry)) continue
    const path = join(directory, entry)
    if (statSync(path).isDirectory()) found.push(...filesMatching(pattern, path))
    else if (pattern.test(entry)) found.push(path)
  }
  return found
}

test('every npm command the documentation gives can actually be run', () => {
  const offenders = []
  for (const path of filesMatching(/\.md$/)) {
    const location = relative(root, path).replaceAll('\\', '/')
    for (const match of readFileSync(path, 'utf8').matchAll(/npm(?:\.cmd)? run ([a-z0-9:_-]+)/g)) {
      if (!scripts.has(match[1])) offenders.push(`${location}: npm run ${match[1]}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these documented commands do not exist, so following the documentation fails:\n  ${offenders.join('\n  ')}`,
  )
})

test('every npm command a workflow runs exists', () => {
  const offenders = []
  for (const path of filesMatching(/\.ya?ml$/, join(root, '.github', 'workflows'))) {
    for (const match of readFileSync(path, 'utf8').matchAll(/npm(?:\.cmd)? run ([a-z0-9:_-]+)/g)) {
      if (!scripts.has(match[1])) offenders.push(`${relative(root, path)}: npm run ${match[1]}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `workflows call scripts that package.json does not define, which only fails once pushed:\n  ${offenders.join('\n  ')}`,
  )
})

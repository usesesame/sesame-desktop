import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

function filesUnder(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name)
    if (statSync(path).isDirectory()) {
      if (name === 'target' || name === 'node_modules') return []
      return filesUnder(path)
    }
    return [path]
  })
}

test('the future desktop repository owns a closed standalone command surface', () => {
  const boundary = JSON.parse(read('desktop-boundary.json'))
  assert.equal(boundary.schemaVersion, 1)
  for (const directory of boundary.directories) {
    assert.ok(statSync(join(root, directory)).isDirectory(), `${directory} is not an owned directory`)
  }
  for (const file of boundary.files) {
    assert.ok(statSync(join(root, file)).isFile(), `${file} is not an owned file`)
  }
  const forbidden = ['website', 'admin', 'backend', 'extensions']
  for (const path of [...boundary.directories, ...boundary.files]) {
    assert.ok(!forbidden.some((part) => path === part || path.startsWith(`${part}/`)), `${path} belongs to a former sibling product`)
  }

  const pkg = JSON.parse(read('package.json'))
  assert.equal(pkg.scripts['desktop:version:check'], 'node tools/version-contract.mjs check')
  assert.equal(pkg.scripts['desktop:contracts'], 'node --test tools/desktop-boundary-contracts.test.mjs')
  assert.match(pkg.scripts['desktop:ci'], /desktop:version:check/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:lint:js/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:contracts/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:check/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:build/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:lint:rust/)
  assert.match(pkg.scripts['desktop:ci'], /cargo test --manifest-path src-tauri\/Cargo\.toml/)
  assert.match(pkg.scripts['desktop:ci'], /--features sync-preview/)
  assert.doesNotMatch(pkg.scripts['desktop:ci'], /website|admin|backend|extension:/)

  const workflowPath = boundary.files.find((file) => file.startsWith('.github/workflows/'))
  assert.ok(workflowPath, 'the boundary manifest declares no owned workflow')
  const workflow = read(...workflowPath.split('/'))
  assert.match(workflow, /node-version-file: \.node-version/)
  assert.match(workflow, /npm ci/)
  assert.match(workflow, /npm run desktop:ci/)
})

test('desktop code and owned checks do not read a former product sibling', () => {
  const sourceFiles = [
    ...filesUnder(join(root, 'src')),
    ...filesUnder(join(root, 'src-tauri', 'src')),
    ...filesUnder(join(root, 'src-tauri', 'tests')),
    join(root, 'vite.config.ts'),
    join(root, 'vitest.config.ts'),
    join(root, 'tools', 'version-contract.mjs'),
  ]
  const siblingRead = /(?:include_(?:str|bytes)!|read_to_string|readFileSync|readFile|new URL)[^\n]*(?:\.\.\/)+(?:backend|website|admin|extensions)(?:\/|\\)/
  const offenders = sourceFiles
    .filter((path) => siblingRead.test(readFileSync(path, 'utf8')))
    .map((path) => relative(root, path).replaceAll('\\', '/'))
  assert.deepEqual(offenders, [], `desktop code reads a former sibling:\n${offenders.join('\n')}`)
})

test('desktop Sync fixtures are digest-bound local snapshots', () => {
  const contractRoot = join(root, 'src-tauri', 'contracts', 'sync', 'v2')
  const source = JSON.parse(readFileSync(join(contractRoot, 'source.json'), 'utf8'))
  assert.equal(source.schemaVersion, 1)
  assert.match(source.sourceCommit, /^[0-9a-f]{40}$/)
  assert.equal(source.sourcePath, 'backend/internal/syncproto/testdata')
  assert.deepEqual(Object.keys(source.files).sort(), [
    'enrollment-signing-payload.json',
    'envelope-signing-payload.json',
    'key-package-signing-payload.json',
    'snapshot-aad.json',
  ])
  for (const [name, expected] of Object.entries(source.files)) {
    const actual = createHash('sha256').update(readFileSync(join(contractRoot, name))).digest('hex')
    assert.equal(actual, expected, `${name} no longer matches its recorded source digest`)
  }

  const rust = read('src-tauri', 'src', 'sync', 'envelope.rs') + read('src-tauri', 'src', 'sync', 'identity.rs')
  for (const name of Object.keys(source.files)) assert.match(rust, new RegExp(name.replaceAll('.', '\\.')))
  assert.doesNotMatch(rust, /\.\.\/backend\/internal\/syncproto\/testdata/)
})

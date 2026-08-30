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

test('the boundary carries every tool the standalone gate executes', () => {
  const boundary = JSON.parse(read('desktop-boundary.json'))
  const pkg = JSON.parse(read('package.json'))
  const inBoundary = (relative) =>
    boundary.files.includes(relative) ||
    boundary.directories.some((directory) => relative.startsWith(`${directory}/`))

  const closure = new Set(['desktop:ci'])
  for (const name of closure) {
    for (const next of (pkg.scripts[name] ?? '').matchAll(/npm run ([a-z:.-]+)/g)) closure.add(next[1])
  }

  const referenced = new Set()
  for (const name of closure) {
    for (const match of (pkg.scripts[name] ?? '').matchAll(/(tools\/[A-Za-z0-9._/-]+\.mjs)/g)) referenced.add(match[1])
  }
  for (const relative of referenced) {
    assert.ok(inBoundary(relative), `${relative} is executed by the standalone gate but is not in desktop-boundary.json`)
  }

  const suites = boundary.files.filter((file) => file.startsWith('tools/') && file.endsWith('.test.mjs'))
  for (const suite of suites) {
    for (const match of read(suite).matchAll(/['"`](tools\/[A-Za-z0-9._/-]+\.mjs)['"`]/g)) {
      assert.ok(inBoundary(match[1]), `${suite} executes ${match[1]} but it is not in desktop-boundary.json`)
    }
  }
})

test('the desktop repository owns a closed standalone command surface', () => {
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
  // Flat glob: tools/cross-repo/ suites read former sibling products.
  assert.equal(pkg.scripts['desktop:contracts'], 'npm run contracts')
  assert.match(pkg.scripts.contracts, /node --test "tools\/\*-contracts\.test\.mjs"/)
  assert.doesNotMatch(pkg.scripts.contracts, /tools\/\*\*/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:version:check/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:lint:js/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:contracts/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:check/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:build/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:lint:rust/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:test:rust/)
  assert.match(pkg.scripts['desktop:ci'], /desktop:test:rust:sync/)
  assert.match(pkg.scripts['desktop:lint:rust'], /cargo fmt --manifest-path src-tauri\/Cargo\.toml --all --check/)
  assert.match(pkg.scripts['desktop:test:rust'], /cargo test --manifest-path src-tauri\/Cargo\.toml$/)
  assert.match(pkg.scripts['desktop:test:rust:sync'], /cargo test --manifest-path src-tauri\/Cargo\.toml --features sync-preview$/)
  assert.doesNotMatch(pkg.scripts['desktop:ci'], /website|admin|backend|extension:/)
  assert.match(pkg.scripts['release:bundle:linux:unsigned'], /^npm run desktop:linux:bundle-prerequisites/)
  assert.match(pkg.scripts['release:bundle:linux:unsigned'], /createUpdaterArtifacts":false/)
  assert.equal(pkg.scripts['desktop:linux:prerequisites'], 'node tools/check-linux-prerequisites.mjs')
  assert.equal(pkg.scripts['desktop:linux:bundle-prerequisites'], 'node tools/check-linux-prerequisites.mjs --bundle')
  assert.equal(pkg.scripts['desktop:linux:dev'], 'npm run desktop:linux:prerequisites && npm run tauri:dev:browser')
  assert.equal(pkg.scripts['tauri:dev:browser'], 'npm run desktop:host:stage && tauri dev')

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

// A command missing from the ACL compiles, ships, and is then denied at runtime.
// Nothing else in the build compares the two lists, so this does.
test('every registered command is reachable through a permission group', () => {
  const lib = read('src-tauri', 'src', 'lib.rs')
  const handler = lib.slice(lib.indexOf('generate_handler!'))
  const registered = [...handler.matchAll(/commands::([a-z0-9_]+)\s*,/g)].map((match) => match[1])
  assert.ok(registered.length > 50, `expected the full command surface, found ${registered.length}`)

  const permissions = read('src-tauri', 'permissions', 'desktop.toml')
  const allowed = new Set([...permissions.matchAll(/"([a-z0-9_]+)"/g)].map((match) => match[1]))

  const unreachable = registered.filter((command) => !allowed.has(command))
  assert.deepEqual(
    unreachable,
    [],
    `these commands are registered but no permission group allows them: ${unreachable.join(', ')}`,
  )
})

// `node --test` exits 0 when a glob matches no file and when a file declares no
// test, so a renamed or emptied suite would otherwise pass by checking nothing.
test('desktop:contracts schedules every tool suite and no empty one', () => {
  const present = readdirSync(join(root, 'tools'), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.test.mjs'))
    .map((entry) => `tools/${entry.name}`)
  assert.ok(present.length > 0, 'tools/ contains no test suites')

  const pkg = JSON.parse(read('package.json'))
  const glob = '"tools/*-contracts.test.mjs"'
  assert.ok(pkg.scripts.contracts.includes(glob), 'the contracts script no longer declares the flat -contracts glob')
  const explicit = [...pkg.scripts.contracts.matchAll(/(tools\/[A-Za-z0-9._/-]+\.test\.mjs)/g)].map((match) => match[1])
  const globbed = present.filter((file) => /-contracts\.test\.mjs$/.test(file))
  const scheduled = new Set([...explicit, ...globbed])

  assert.deepEqual(
    present.filter((file) => !scheduled.has(file)),
    [],
    `these suites exist but desktop:contracts never runs them: ${present.filter((file) => !scheduled.has(file)).join(', ')}`,
  )
  assert.deepEqual(
    [...scheduled].filter((file) => !present.includes(file)),
    [],
    `desktop:contracts schedules suites that do not exist: ${[...scheduled].filter((file) => !present.includes(file)).join(', ')}`,
  )

  for (const file of present) {
    assert.match(read(...file.split('/')), /\btest\(/, `${file} declares no test, so it passes without checking anything`)
  }
})

test('no npm script passes by announcing a skip', () => {
  const pkg = JSON.parse(read('package.json'))
  const skippers = Object.entries(pkg.scripts)
    .filter(([, command]) => /skip-with-message/.test(command))
    .map(([name]) => name)
  assert.deepEqual(
    skippers,
    [],
    `these scripts report a pass without checking anything: ${skippers.join(', ')}`,
  )
})

import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const tauri = join(root, 'src-tauri')
const read = (...parts) => readFileSync(join(tauri, ...parts), 'utf8')

function rustFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'target' ? [] : rustFiles(path)
    return name.endsWith('.rs') ? [path] : []
  })
}

function workspaceMembers() {
  const manifest = read('Cargo.toml')
  const members = /^members\s*=\s*\[([^\]]*)\]/m.exec(manifest)
  assert.ok(members, 'src-tauri/Cargo.toml no longer lists its workspace members on one line')
  return [...members[1].matchAll(/"([^"]+)"/g)].map((match) => match[1])
}

function callArguments(source, start) {
  let depth = 0
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === '(') depth += 1
    if (source[index] === ')') {
      depth -= 1
      if (depth === 0) return source.slice(start, index + 1)
    }
  }
  throw new Error('unbalanced call')
}

test('only the application crate reads its own package version', () => {
  const members = workspaceMembers()
  assert.ok(members.includes('sesame-app'))
  for (const member of members) {
    for (const file of rustFiles(join(tauri, member))) {
      const source = readFileSync(file, 'utf8')
      assert.doesNotMatch(
        source,
        /CARGO_PKG_VERSION/,
        `${file.slice(root.length + 1)} reads its own crate version, which is not the release version`,
      )
    }
  }
})

test('the application version is the release version the version contract keeps in step', () => {
  const identity = read('src', 'adapters', 'platform', 'app_identity.rs')
  assert.match(identity, /^pub const APP_VERSION: &str = env!\("CARGO_PKG_VERSION"\);$/m)
  const manifest = read('Cargo.toml')
  const packageSection = /^\[package\]\s*\n([\s\S]*?)(?=^\[)/m.exec(manifest)
  assert.match(packageSection[1], /^name = "sesame"$/m)
  const releaseVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version
  assert.match(packageSection[1], new RegExp(`^version = "${releaseVersion.replaceAll('.', '\\.')}"$`, 'm'))
})

test('every server version check the application starts passes the release version', () => {
  const checks = [
    'inspect_server',
    'verify_pinned_server',
    'pinned_server_time',
    'require_desktop_linking',
    'SyncClient::for_target',
  ]
  const seen = new Map(checks.map((name) => [name, 0]))
  for (const file of rustFiles(join(tauri, 'src'))) {
    const source = readFileSync(file, 'utf8')
    for (const name of checks) {
      const pattern = new RegExp(`(?<![\\w:])${name}\\(`, 'g')
      for (const match of source.matchAll(pattern)) {
        if (/fn\s+$/.test(source.slice(Math.max(0, match.index - 4), match.index))) continue
        const call = callArguments(source, match.index + name.length)
        assert.match(
          call,
          /\bAPP_VERSION\b/,
          `${file.slice(root.length + 1)} calls ${name} without the release version`,
        )
        seen.set(name, seen.get(name) + 1)
      }
    }
  }
  for (const [name, count] of seen) {
    assert.ok(count > 0, `the application no longer calls ${name}, so update this test`)
  }
})

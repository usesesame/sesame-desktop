import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { checkAdmission, checkWorkspace, parseDirectDependencies } from './dependency-admission.mjs'

test('the real workspace passes the admission gate', () => {
  const result = checkWorkspace()
  assert.deepEqual(result.unadmitted, [])
  assert.deepEqual(result.stale, [])
  assert.deepEqual(result.mismatched, [])
})

test('the parser reads plain, table, target-specific, and workspace entries', () => {
  const dependencies = parseDirectDependencies(`
[dependencies]
serde = "1"
tauri = { version = "2", features = ["tray-icon"] }
# a comment with serde = "9" inside must not parse
sesame-core = { path = "sesame-core" }

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.61", features = ["Win32_Foundation"] }

[dev-dependencies]
testing-only = "1"

[profile.release]
strip = "none"
`)
  assert.deepEqual(dependencies.get('serde'), { version: '1', path: false })
  assert.deepEqual(dependencies.get('tauri'), { version: '2', path: false })
  assert.deepEqual(dependencies.get('windows-sys'), { version: '0.61', path: false })
  assert.deepEqual(dependencies.get('sesame-core'), { version: null, path: true })
  assert.equal(dependencies.get('testing-only'), undefined)
  assert.equal(dependencies.get('strip'), undefined)
})

test('unadmitted, stale, and version-mismatched entries all fail the gate', () => {
  const manifests = new Map([
    ['Cargo.toml', '[dependencies]\nargon2 = "0.6"\nnewdep = "1.2"\n'],
    ['sesame-core/Cargo.toml', '[dependencies]\nserde = "1"\n'],
  ])
  const result = checkAdmission(manifests, {
    schemaVersion: 1,
    packages: [
      { name: 'argon2', version: '0.6' },
      { name: 'serde', version: '1' },
      { name: 'departed', version: '9' },
    ],
  })
  assert.ok(result.unadmitted.some((line) => line.includes('newdep')))
  assert.ok(result.stale.includes('departed'))
  assert.deepEqual(result.mismatched, [])
  const mismatch = checkAdmission(manifests, {
    schemaVersion: 1,
    packages: [{ name: 'serde', version: '0.9' }],
  })
  assert.ok(mismatch.mismatched.some((line) => line.includes('serde')))
  assert.throws(() => checkAdmission(manifests, { schemaVersion: 2, packages: [] }), /schemaVersion 1/)
})

test('duplicate admissions are refused', () => {
  const manifests = new Map([['Cargo.toml', '[dependencies]\nserde = "1"\n']])
  assert.throws(
    () => checkAdmission(manifests, { schemaVersion: 1, packages: [{ name: 'serde', version: '1' }, { name: 'serde', version: '1' }] }),
    /more than once/,
  )
})

test('the gate runs against a fixture workspace on disk', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-admission-'))
  try {
    await mkdir(path.join(root, 'src-tauri', 'sesame-core'), { recursive: true })
    await writeFile(path.join(root, 'src-tauri', 'Cargo.toml'), '[dependencies]\nserde = "1"\n')
    await writeFile(path.join(root, 'src-tauri', 'sesame-core', 'Cargo.toml'), '[dependencies]\n')
    await writeFile(
      path.join(root, 'src-tauri', 'dependency-admission.json'),
      `${JSON.stringify({ schemaVersion: 1, packages: [{ name: 'serde', version: '1', reason: 'fixture' }] }, null, 2)}\n`,
    )
    const passing = checkWorkspace({ manifestRoot: root })
    assert.deepEqual(passing.unadmitted, [])
    await writeFile(path.join(root, 'src-tauri', 'Cargo.toml'), '[dependencies]\nserde = "1"\nunreviewed = "1"\n')
    const failing = checkWorkspace({ manifestRoot: root })
    assert.ok(failing.unadmitted.some((line) => line.includes('unreviewed')))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

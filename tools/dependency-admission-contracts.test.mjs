import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { checkAdmission, checkWorkspace, matchesVersion } from './dependency-admission.mjs'

const cratesIo = 'registry+https://github.com/rust-lang/crates.io-index'
const workspaceId = 'path+file:///fixture/sesame#0.3.0'
const checksum = (letter) => letter.repeat(64)

function cargoFixture({ packages = [], direct = [] }) {
  const blocks = packages.map((pkg) => {
    const lines = ['[[package]]', `name = "${pkg.name}"`, `version = "${pkg.version}"`]
    if (pkg.source) lines.push(`source = "${pkg.source}"`)
    if (pkg.checksum) lines.push(`checksum = "${pkg.checksum}"`)
    return lines.join('\n')
  })
  return {
    lock: ['version = 4', '', ...blocks].join('\n\n') + '\n',
    metadata: {
      workspace_members: [workspaceId],
      packages: [
        { id: workspaceId, name: 'sesame', version: '0.3.0', source: null },
        ...packages.map((pkg) => ({ id: `${pkg.name}@${pkg.version}`, name: pkg.name, version: pkg.version, source: pkg.source ?? null })),
      ],
      resolve: {
        nodes: [
          {
            id: workspaceId,
            deps: direct.map((dep) => ({
              name: dep.name,
              pkg: `${dep.name}@${dep.version}`,
              dep_kinds: dep.kinds ?? [{ kind: null, target: null }],
            })),
          },
        ],
      },
    },
  }
}

function npmFixture({ direct = {}, packages = [] }) {
  const lockPackages = { '': { name: 'sesame', version: '0.3.0', dependencies: direct } }
  for (const pkg of packages) {
    lockPackages[`node_modules/${pkg.name}`] = {
      version: pkg.version,
      ...(pkg.resolved === null ? {} : { resolved: pkg.resolved ?? `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz` }),
      ...(pkg.integrity === null ? {} : { integrity: pkg.integrity ?? 'sha512-fixture' }),
    }
  }
  return `${JSON.stringify({ name: 'sesame', version: '0.3.0', lockfileVersion: 3, packages: lockPackages }, null, 2)}\n`
}

function admissionOf(entries) {
  return { schemaVersion: 1, packages: entries.map((entry) => ({ reason: 'Fixture admission.', ...entry })) }
}

function check(fixture, admission, npmLock = npmFixture({})) {
  return checkAdmission({ cargoLock: fixture.lock, npmLock, metadata: fixture.metadata, admission })
}

test('the current tree passes the admission gate', () => {
  const result = checkWorkspace()
  assert.deepEqual(result.foreignSources, [])
  assert.deepEqual(result.missingChecksums, [])
  assert.deepEqual(result.missingIntegrity, [])
  assert.deepEqual(result.unadmitted, [])
  assert.deepEqual(result.mismatched, [])
  assert.deepEqual(result.stale, [])
})

test('a git-sourced package fails the source check', () => {
  const fixture = cargoFixture({
    packages: [
      { name: 'argon2', version: '0.6.0', source: cratesIo, checksum: checksum('a') },
      { name: 'sketchy-crate', version: '1.2.3', source: 'git+https://example.invalid/sketchy-crate#0123456789abcdef0123456789abcdef01234567' },
    ],
    direct: [{ name: 'argon2', version: '0.6.0' }],
  })
  const result = check(fixture, admissionOf([{ name: 'argon2', version: '0.6' }]))
  assert.ok(result.foreignSources.some((line) => line.includes('sketchy-crate')))
  assert.deepEqual(result.missingChecksums, [])
})

test('a registry package without a checksum fails', () => {
  const fixture = cargoFixture({
    packages: [{ name: 'argon2', version: '0.6.0', source: cratesIo }],
    direct: [{ name: 'argon2', version: '0.6.0' }],
  })
  const result = check(fixture, admissionOf([{ name: 'argon2', version: '0.6' }]))
  assert.ok(result.missingChecksums.some((line) => line.includes('argon2')))
})

test('a locked version outside the admitted line fails', () => {
  const fixture = cargoFixture({
    packages: [{ name: 'argon2', version: '0.7.0', source: cratesIo, checksum: checksum('a') }],
    direct: [{ name: 'argon2', version: '0.7.0' }],
  })
  const result = check(fixture, admissionOf([{ name: 'argon2', version: '0.6' }]))
  assert.ok(result.mismatched.some((line) => line.includes('argon2')))
  assert.equal(matchesVersion('0.6.9', '0.6'), true)
  assert.equal(matchesVersion('0.60.1', '0.6'), false)
})

test('a direct dependency without an admitted entry fails', () => {
  const fixture = cargoFixture({
    packages: [
      { name: 'argon2', version: '0.6.0', source: cratesIo, checksum: checksum('a') },
      { name: 'unknown-crate', version: '1.0.0', source: cratesIo, checksum: checksum('b') },
    ],
    direct: [
      { name: 'argon2', version: '0.6.0' },
      { name: 'unknown-crate', version: '1.0.0', kinds: [{ kind: 'build', target: null }] },
    ],
  })
  const result = check(fixture, admissionOf([{ name: 'argon2', version: '0.6' }]))
  assert.ok(result.unadmitted.some((line) => line.includes('unknown-crate')))
})

test('npm packages need registry.npmjs.org and an integrity hash', () => {
  const fixture = cargoFixture({
    packages: [{ name: 'argon2', version: '0.6.0', source: cratesIo, checksum: checksum('a') }],
    direct: [{ name: 'argon2', version: '0.6.0' }],
  })
  const npmLock = npmFixture({
    direct: { 'renderer-kit': '^3.0.0' },
    packages: [
      { name: 'renderer-kit', version: '3.1.0', resolved: 'https://example.invalid/renderer-kit-3.1.0.tgz' },
      { name: 'builder-tool', version: '4.0.0', integrity: null },
    ],
  })
  const result = check(
    fixture,
    admissionOf([
      { name: 'argon2', version: '0.6' },
      { name: 'renderer-kit', version: '3.1', source: 'npm' },
    ]),
    npmLock,
  )
  assert.ok(result.foreignSources.some((line) => line.includes('renderer-kit')))
  assert.ok(result.missingIntegrity.some((line) => line.includes('builder-tool')))
})

test('a source-less package needs an admitted path entry', () => {
  const fixture = cargoFixture({
    packages: [{ name: 'vendored-ui', version: '2.0.0' }],
    direct: [{ name: 'vendored-ui', version: '2.0.0', kinds: [{ kind: 'dev', target: null }] }],
  })
  const missing = check(fixture, admissionOf([]))
  assert.ok(missing.foreignSources.some((line) => line.includes('vendored-ui')))
  const admitted = check(fixture, admissionOf([{ name: 'vendored-ui', version: '2.0', source: 'path' }]))
  assert.deepEqual(admitted.foreignSources, [])
  assert.deepEqual(admitted.unadmitted, [])
  assert.deepEqual(admitted.stale, [])
})

test('an admission with no matching direct dependency is stale', () => {
  const fixture = cargoFixture({
    packages: [{ name: 'argon2', version: '0.6.0', source: cratesIo, checksum: checksum('a') }],
    direct: [{ name: 'argon2', version: '0.6.0' }],
  })
  const result = check(fixture, admissionOf([{ name: 'argon2', version: '0.6' }, { name: 'departed-crate', version: '9' }]))
  assert.ok(result.stale.some((line) => line.includes('departed-crate')))
})

test('the admission file refuses duplicates, missing reasons, and bad versions', () => {
  const fixture = cargoFixture({})
  assert.throws(
    () => check(fixture, admissionOf([{ name: 'argon2', version: '0.6' }, { name: 'argon2', version: '0.6' }])),
    /more than once/,
  )
  assert.throws(() => check(fixture, { schemaVersion: 1, packages: [{ name: 'argon2', version: '0.6', reason: ' ' }] }), /reason/)
  assert.throws(() => check(fixture, { schemaVersion: 1, packages: [{ name: 'argon2', version: 'latest', reason: 'Fixture admission.' }] }), /version/)
  assert.throws(() => check(fixture, { schemaVersion: 2, packages: [] }), /schemaVersion 1/)
})

test('the gate reads a fixture workspace from disk', async () => {
  const fixture = cargoFixture({
    packages: [{ name: 'argon2', version: '0.6.0', source: cratesIo, checksum: checksum('a') }],
    direct: [{ name: 'argon2', version: '0.6.0' }],
  })
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-admission-'))
  try {
    await mkdir(path.join(root, 'src-tauri'), { recursive: true })
    await writeFile(path.join(root, 'src-tauri', 'Cargo.lock'), fixture.lock)
    await writeFile(path.join(root, 'package-lock.json'), npmFixture({}))
    const admissionPath = path.join(root, 'src-tauri', 'dependency-admission.json')
    await writeFile(admissionPath, `${JSON.stringify(admissionOf([{ name: 'argon2', version: '0.6' }]), null, 2)}\n`)
    const passing = checkWorkspace({ manifestRoot: root, metadata: fixture.metadata })
    assert.deepEqual(passing.unadmitted, [])
    await writeFile(admissionPath, `${JSON.stringify(admissionOf([]), null, 2)}\n`)
    const failing = checkWorkspace({ manifestRoot: root, metadata: fixture.metadata })
    assert.ok(failing.unadmitted.some((line) => line.includes('argon2')))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('a lockfile that cannot resolve fails the gate', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-admission-lock-'))
  try {
    await mkdir(path.join(root, 'src-tauri', 'src'), { recursive: true })
    await writeFile(path.join(root, 'src-tauri', 'Cargo.toml'), '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n')
    await writeFile(path.join(root, 'src-tauri', 'src', 'lib.rs'), '')
    await writeFile(
      path.join(root, 'src-tauri', 'Cargo.lock'),
      `version = 4\n\n[[package]]\nname = "ghost"\nversion = "1.0.0"\nsource = "${cratesIo}"\nchecksum = "${checksum('a')}"\n`,
    )
    await writeFile(path.join(root, 'package-lock.json'), npmFixture({}))
    await writeFile(path.join(root, 'src-tauri', 'dependency-admission.json'), `${JSON.stringify({ schemaVersion: 1, packages: [] }, null, 2)}\n`)
    assert.throws(() => checkWorkspace({ manifestRoot: root }), /does not resolve|could not run/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

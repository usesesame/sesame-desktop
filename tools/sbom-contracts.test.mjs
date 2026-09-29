import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { vendorTreeDigest } from './create-sbom.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version

function readNpmLock() {
  return JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'))
}

function lockName(location, entry) {
  return entry.name ?? location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length)
}

function generate() {
  const output = mkdtempSync(join(tmpdir(), 'sesame-sbom-'))
  try {
    execFileSync(process.execPath, [join(root, 'tools', 'create-sbom.mjs')], {
      cwd: root,
      env: { ...process.env, SESAME_SBOM_OUTPUT_DIR: output },
    })
    return {
      bom: JSON.parse(readFileSync(join(output, `sesame-${version}.cdx.json`), 'utf8')),
      provenance: JSON.parse(readFileSync(join(output, `sesame-${version}.provenance.json`), 'utf8')),
    }
  } finally {
    rmSync(output, { recursive: true, force: true })
  }
}

test('the bill of materials records a hash and an accurate scope for every npm package', () => {
  const { bom } = generate()
  assert.ok(bom.components.length > 500, 'the bill of materials is missing most of the graph')
  const registry = bom.components.filter((component) => component.purl.startsWith('pkg:cargo/'))
  const withoutHash = registry.filter((component) => !component.hashes?.length)
  const pathSources = withoutHash.filter((component) =>
    component.properties?.some((property) => property.name === 'sesame:source' && property.value === 'path'),
  )
  assert.deepEqual(
    withoutHash.map((component) => component.name).sort(),
    pathSources.map((component) => component.name).sort(),
    'a registry package has no checksum and is not declared as a path source',
  )
  const scopes = new Map()
  for (const [location, entry] of Object.entries(readNpmLock().packages ?? {})) {
    if (!location.includes('node_modules/')) continue
    scopes.set(`${lockName(location, entry)}@${entry.version}`, entry.dev ? 'optional' : 'required')
  }
  const npm = bom.components.filter((component) => component.purl.startsWith('pkg:npm/'))
  assert.ok(npm.length > 100, 'the npm packages are missing')
  assert.ok(npm.some((component) => component.scope === 'optional'), 'no build-time npm package is marked optional')
  assert.ok(npm.some((component) => component.scope === 'required'), 'no shipped npm package is marked required')
  for (const component of npm) {
    assert.ok(component.hashes?.length === 1, `${component.name} has no integrity hash`)
    assert.equal(
      component.scope,
      scopes.get(`${component.name}@${component.version}`),
      `${component.name} has the wrong scope for its lock entry`,
    )
  }
})

test('aliased npm packages are recorded under the real package name', () => {
  const { bom } = generate()
  const aliases = Object.entries(readNpmLock().packages ?? {}).filter(
    ([location, entry]) => location.includes('node_modules/') && entry.name,
  )
  assert.ok(aliases.length > 0, 'the lockfile has no aliased packages, so this test would prove nothing')
  const npm = bom.components.filter((component) => component.purl.startsWith('pkg:npm/'))
  for (const [location, entry] of aliases) {
    assert.ok(
      npm.some(
        (component) =>
          component.name === entry.name &&
          component.version === entry.version &&
          component.purl === `pkg:npm/${entry.name}@${entry.version}`,
      ),
      `${location} is not recorded as ${entry.name}@${entry.version}`,
    )
  }
})

test('the vendored glib tree is recorded by digest', () => {
  const { bom, provenance } = generate()
  const glib = bom.components.find((component) => component.name === 'glib' && component.purl.startsWith('pkg:cargo/'))
  assert.ok(glib, 'the vendored glib package is missing')
  const property = glib.properties?.find((entry) => entry.name === 'sesame:vendor-tree-sha256')
  assert.match(property?.value ?? '', /^[0-9a-f]{64}$/)
  assert.equal(provenance.source.vendorTreeSha256, property.value)
})

test('the vendored tree digest hashes forward-slash relative paths in a nested tree', async () => {
  const tree = mkdtempSync(join(tmpdir(), 'sesame-vendor-tree-'))
  try {
    mkdirSync(join(tree, 'nested', 'deeper'), { recursive: true })
    writeFileSync(join(tree, 'top.txt'), 'fictional top')
    writeFileSync(join(tree, 'nested', 'deeper', 'leaf.txt'), 'fictional leaf')
    const expected = createHash('sha256')
    for (const [relative, content] of [
      ['nested/deeper/leaf.txt', 'fictional leaf'],
      ['top.txt', 'fictional top'],
    ]) {
      expected.update(relative)
      expected.update('\0')
      expected.update(content)
      expected.update('\0')
    }
    assert.equal(await vendorTreeDigest(tree, tree), expected.digest('hex'))
  } finally {
    rmSync(tree, { recursive: true, force: true })
  }
})

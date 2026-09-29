import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version

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

test('the bill of materials records a hash for every registry package', () => {
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
  const npm = bom.components.filter((component) => component.purl.startsWith('pkg:npm/'))
  assert.ok(npm.length > 100, 'the npm packages are missing')
  for (const component of npm) {
    assert.ok(component.hashes?.length === 1, `${component.name} has no integrity hash`)
    assert.ok(['required', 'excluded'].includes(component.scope), `${component.name} has no scope`)
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

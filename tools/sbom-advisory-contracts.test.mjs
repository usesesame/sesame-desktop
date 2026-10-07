import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { auditSbom, collectAdvisories, defaultSbomPath } from './audit-sbom.mjs'

const root = path.resolve(import.meta.dirname, '..')
const component = (name, version, purl) => ({ type: 'library', name, version, purl })

test('a component with an OSV advisory fails the audit with its name, version, and advisory id', async () => {
  const bom = {
    components: [component('fictional-vulnerable', '1.2.3', 'pkg:npm/fictional-vulnerable@1.2.3')],
  }
  await assert.rejects(
    auditSbom(bom, { query: async () => [{ id: 'GHSA-fictional-0001' }] }),
    (error) => {
      assert.match(error.message, /fictional-vulnerable@1\.2\.3: GHSA-fictional-0001/)
      assert.equal(error.report.vulnerable.length, 1)
      return true
    },
  )
})

test('a component with no OSV advisories passes the audit', async () => {
  const bom = { components: [component('fictional-clean', '2.0.0', 'pkg:cargo/fictional-clean@2.0.0')] }
  const report = await auditSbom(bom, { query: async () => [] })
  assert.equal(report.vulnerable.length, 0)
  assert.equal(report.queried, 1)
})

test('a component without a purl is skipped and never queried', async () => {
  const purls = []
  const bom = {
    components: [
      component('fictional-skipped', '1.0.0', undefined),
      component('fictional-clean', '1.0.0', 'pkg:npm/fictional-clean@1.0.0'),
    ],
  }
  const report = await collectAdvisories(bom, {
    query: async (purl) => {
      purls.push(purl)
      return []
    },
  })
  assert.deepEqual(purls, ['pkg:npm/fictional-clean@1.0.0'])
  assert.equal(report.total, 2)
  assert.equal(report.queried, 1)
  assert.equal(report.skipped, 1)
})

test('the coverage counts and ecosystem breakdown are reported', async () => {
  const bom = {
    components: [
      component('fictional-npm-a', '1.0.0', 'pkg:npm/fictional-npm-a@1.0.0'),
      component('fictional-npm-b', '1.0.0', 'pkg:npm/fictional-npm-b@1.0.0'),
      component('fictional-cargo', '1.0.0', 'pkg:cargo/fictional-cargo@1.0.0'),
      component('fictional-unpurl', '1.0.0', undefined),
    ],
  }
  const report = await collectAdvisories(bom, { query: async () => [] })
  assert.equal(report.total, 4)
  assert.equal(report.queried, 3)
  assert.equal(report.skipped, 1)
  assert.deepEqual(report.byEcosystem, { npm: 2, cargo: 1 })
})

test('queries run with bounded concurrency', async () => {
  const bom = {
    components: Array.from({ length: 12 }, (_, index) =>
      component(`fictional-${index}`, '1.0.0', `pkg:npm/fictional-${index}@1.0.0`),
    ),
  }
  let active = 0
  let peak = 0
  await collectAdvisories(bom, {
    concurrency: 3,
    query: async () => {
      active += 1
      peak = Math.max(peak, active)
      await new Promise((resolve) => setImmediate(resolve))
      active -= 1
      return []
    },
  })
  assert.equal(peak, 3)
})

test('the default SBOM path matches the file create-sbom writes', () => {
  const previous = process.env.SESAME_SBOM_OUTPUT_DIR
  delete process.env.SESAME_SBOM_OUTPUT_DIR
  try {
    const version = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version
    assert.equal(defaultSbomPath(root), path.join(root, 'release-evidence', `sesame-${version}.cdx.json`))
  } finally {
    if (previous !== undefined) process.env.SESAME_SBOM_OUTPUT_DIR = previous
  }
})

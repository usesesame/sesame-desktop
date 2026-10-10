import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  auditSbom,
  auditSboms,
  collectAdvisories,
  collectSbomAdvisories,
  defaultSbomPath,
  loadAllowlist,
} from './audit-sbom.mjs'

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

test('the audit covers every SBOM passed to it and labels findings by source', async () => {
  const sources = [
    {
      label: 'locked.cdx.json',
      bom: { components: [component('fictional-clean', '1.0.0', 'pkg:npm/fictional-clean@1.0.0')] },
    },
    {
      label: 'appimage.cdx.json',
      bom: { components: [component('fictional-bundled', '2.0.0', 'pkg:deb/ubuntu/fictional-bundled@2.0.0')] },
    },
  ]
  const query = async (purl) => (purl.includes('fictional-bundled') ? [{ id: 'UBUNTU-CVE-fictional-0001' }] : [])
  const report = await collectSbomAdvisories(sources, { query })
  assert.equal(report.total, 2)
  assert.equal(report.queried, 2)
  assert.equal(report.skipped, 0)
  assert.deepEqual(report.byEcosystem, { npm: 1, deb: 1 })
  assert.equal(report.vulnerable.length, 1)
  assert.equal(report.vulnerable[0].label, 'appimage.cdx.json')
  assert.equal(report.sources[1].vulnerable.length, 1)
  await assert.rejects(
    auditSboms(sources, { query }),
    /appimage\.cdx\.json: fictional-bundled@2\.0\.0: UBUNTU-CVE-fictional-0001/,
  )
})

test('a clean locked SBOM and a clean AppImage inventory pass the combined audit', async () => {
  const sources = [
    {
      label: 'locked.cdx.json',
      bom: { components: [component('fictional-clean', '1.0.0', 'pkg:npm/fictional-clean@1.0.0')] },
    },
    {
      label: 'appimage.cdx.json',
      bom: {
        components: [
          component('fictional-bundled', '2.0.0', 'pkg:deb/ubuntu/fictional-bundled@2.0.0'),
          component('fictional-unpurl', '2.0.0', undefined),
        ],
      },
    },
  ]
  const report = await auditSboms(sources, { query: async () => [] })
  assert.equal(report.vulnerable.length, 0)
  assert.equal(report.queried, 2)
  assert.equal(report.skipped, 1)
})

const systemdSource = () => [
  {
    label: 'appimage.cdx.json',
    bom: {
      components: [
        component('systemd', '255.4-1ubuntu8.17', 'pkg:deb/ubuntu/systemd@255.4-1ubuntu8.17'),
      ],
    },
  },
]

const systemdRule = () => [
  {
    id: 'UBUNTU-CVE-2026-40228',
    package: 'systemd',
    reason: 'The journald daemon is not bundled and noble has no fix.',
    reviewed: '2026-10-07',
  },
]

test('an allowlisted advisory passes and is reported', async () => {
  const report = await auditSboms(systemdSource(), {
    query: async () => [{ id: 'UBUNTU-CVE-2026-40228' }],
    allowlist: systemdRule(),
  })
  assert.equal(report.vulnerable.length, 0)
  assert.equal(report.allowed.length, 1)
  assert.equal(report.allowed[0].name, 'systemd')
  assert.deepEqual(report.unused, [])
})

test('an allowlist entry for another package does not suppress the advisory', async () => {
  const rule = systemdRule()
  rule[0].package = 'another-package'
  await assert.rejects(
    auditSboms(systemdSource(), { query: async () => [{ id: 'UBUNTU-CVE-2026-40228' }], allowlist: rule }),
    /systemd@255\.4-1ubuntu8\.17: UBUNTU-CVE-2026-40228/,
  )
})

test('one unlisted advisory in a component still fails the audit', async () => {
  await assert.rejects(
    auditSboms(systemdSource(), {
      query: async () => [{ id: 'UBUNTU-CVE-2026-40228' }, { id: 'UBUNTU-CVE-other' }],
      allowlist: systemdRule(),
    }),
    /UBUNTU-CVE-other/,
  )
})

test('an unused allowlist entry is reported', async () => {
  const sources = [
    {
      label: 'locked.cdx.json',
      bom: { components: [component('fictional-clean', '1.0.0', 'pkg:npm/fictional-clean@1.0.0')] },
    },
  ]
  const report = await auditSboms(sources, { query: async () => [], allowlist: systemdRule() })
  assert.equal(report.unused.length, 1)
  assert.equal(report.unused[0].id === 'UBUNTU-CVE-2026-40228', true)
})

test('an allowlist entry without a reason is rejected', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'sesame-allowlist-'))
  const file = path.join(directory, 'allowlist.json')
  writeFileSync(file, JSON.stringify({ entries: [{ id: 'X', package: 'y', reviewed: '2026-10-07' }] }))
  try {
    assert.throws(() => loadAllowlist(file), /reason/)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('the shipped allowlist names the systemd advisory with a reason and a review date', () => {
  const entry = loadAllowlist().find((rule) => rule.id === 'UBUNTU-CVE-2026-40228')
  assert.ok(entry, 'the systemd advisory entry is gone from the allowlist')
  assert.equal(entry.package, 'systemd')
  assert.ok(entry.reason.length > 20, 'the entry needs a reason a reviewer can check')
  assert.match(entry.reviewed, /^\d{4}-\d{2}-\d{2}$/)
})

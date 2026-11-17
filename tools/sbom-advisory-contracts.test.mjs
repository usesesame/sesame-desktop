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
  awaitsUbuntuFix,
  isWithdrawn,
  onlyUnmaintained,
  loadAllowlist,
  loadUnfixedLibraryRules,
  queryOsv,
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

test('obsolete PCRE2 exceptions cannot hide the vulnerable bundled version', async () => {
  const bom = { components: [component('pcre2', '10.42-4ubuntu2.1', 'pkg:deb/ubuntu/pcre2@10.42-4ubuntu2.1')] }
  await assert.rejects(
    auditSboms([{ bom }], {
      query: async () => [{ id: 'UBUNTU-CVE-2026-103111' }],
      today: '2026-11-06',
    }),
    /pcre2@10\.42-4ubuntu2\.1: UBUNTU-CVE-2026-103111/,
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

test('the shipped allowlist keeps a reason and a review date on the high priority WebKitGTK advisory', () => {
  const entry = loadAllowlist().find((rule) => rule.id === 'UBUNTU-CVE-2026-3909')
  assert.ok(entry, 'the high priority WebKitGTK advisory entry is gone from the allowlist')
  assert.equal(entry.package, 'webkit2gtk')
  assert.ok(entry.reason.length > 20, 'the entry needs a reason a reviewer can check')
  assert.match(entry.reviewed, /^\d{4}-\d{2}-\d{2}$/)
})

test('an expired allowlist entry no longer suppresses its advisory', async () => {
  const bom = { components: [{ name: 'systemd', version: '255', purl: 'pkg:deb/ubuntu/systemd@255' }] }
  const query = async () => [{ id: 'UBUNTU-CVE-2026-40228' }]
  const rule = { id: 'UBUNTU-CVE-2026-40228', package: 'systemd', reason: 'checked', reviewed: '2026-10-07', expires: '2026-11-17' }
  const open = await collectSbomAdvisories([{ bom }], { query, allowlist: [rule], today: '2026-11-17' })
  assert.equal(open.vulnerable.length, 0)
  const lapsed = await collectSbomAdvisories([{ bom }], { query, allowlist: [rule], today: '2026-11-18' })
  assert.equal(lapsed.vulnerable.length, 1)
  assert.deepEqual(lapsed.expired.map((entry) => entry.id), ['UBUNTU-CVE-2026-40228'])
})

test('an allowlist entry must carry an expiry within ninety days of its review', () => {
  const write = (entry) => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), 'allowlist-')), 'allowlist.json')
    writeFileSync(file, JSON.stringify({ entries: [entry] }))
    return file
  }
  const base = { id: 'X-1', package: 'p', reason: 'checked', reviewed: '2026-10-07' }
  assert.throws(() => loadAllowlist(write(base)), /expiry date/)
  assert.throws(() => loadAllowlist(write({ ...base, expires: '2027-06-01' })), /within 90 days/)
  assert.throws(() => loadAllowlist(write({ ...base, expires: '2026-10-01' })), /within 90 days/)
  assert.throws(() => loadAllowlist(write({ ...base, reviewed: '2027-02-30', expires: '2027-03-03' })), /expiry date/)
  assert.throws(() => loadAllowlist(write({ ...base, expires: '2026-11-31' })), /expiry date/)
  assert.equal(loadAllowlist(write({ ...base, expires: '2026-12-01' })).length, 1)
})

test('every shipped allowlist entry expires within ninety days of its review', () => {
  for (const entry of loadAllowlist()) {
    assert.ok(entry.expires > entry.reviewed, entry.id)
  }
})

test('OSV pagination collects advisories from every response', async (t) => {
  const requests = []
  const pages = [
    { vulns: [{ id: 'GHSA-fictional-first' }], next_page_token: 'fictional-page-two' },
    { next_page_token: 'fictional-page-three' },
    { vulns: [{ id: 'GHSA-fictional-last' }] },
  ]
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    requests.push(JSON.parse(options.body))
    return { ok: true, json: async () => pages.shift() }
  })
  const purl = 'pkg:npm/fictional-package@1.0.0'
  const vulnerabilities = await queryOsv(purl)
  assert.deepEqual(
    vulnerabilities.map((vulnerability) => vulnerability.id),
    ['GHSA-fictional-first', 'GHSA-fictional-last'],
  )
  assert.deepEqual(requests, [
    { package: { purl } },
    { package: { purl }, page_token: 'fictional-page-two' },
    { package: { purl }, page_token: 'fictional-page-three' },
  ])
})

test('an OSV continuation with no advisories cannot hide a later finding', async (t) => {
  const pages = [
    { next_page_token: 'fictional-page-two' },
    { vulns: [{ id: 'GHSA-fictional-hidden' }] },
  ]
  t.mock.method(globalThis, 'fetch', async () => ({ ok: true, json: async () => pages.shift() }))
  await assert.rejects(
    auditSbom({ components: [component('fictional-package', '1.0.0', 'pkg:npm/fictional-package@1.0.0')] }),
    /GHSA-fictional-hidden/,
  )
})

test('a failed OSV continuation refuses the audit', async (t) => {
  let calls = 0
  t.mock.method(globalThis, 'fetch', async () => {
    calls += 1
    return calls === 1
      ? { ok: true, json: async () => ({ next_page_token: 'fictional-page-two' }) }
      : { ok: false, status: 503 }
  })
  await assert.rejects(queryOsv('pkg:npm/fictional-package@1.0.0'), /HTTP 503/)
  assert.equal(calls, 2)
})

test('a repeated OSV continuation token refuses the audit', async (t) => {
  let calls = 0
  t.mock.method(globalThis, 'fetch', async () => {
    calls += 1
    return { ok: true, json: async () => ({ next_page_token: 'fictional-repeated-page' }) }
  })
  await assert.rejects(queryOsv('pkg:npm/fictional-package@1.0.0'), /repeated continuation token/)
  assert.equal(calls, 2)
})

const noble = 'Ubuntu:24.04:LTS'
const ubuntuAdvisory = ({ id = 'UBUNTU-CVE-fictional-1', priority = 'medium', name = 'fictional-lib', release = noble, fixed } = {}) => ({
  id,
  ...(priority ? { severity: [{ type: 'Ubuntu', score: priority }] } : {}),
  affected: [
    {
      package: { ecosystem: release, name },
      ranges: [{ type: 'ECOSYSTEM', events: fixed ? [{ introduced: '0' }, { fixed }] : [{ introduced: '0' }] }],
    },
  ],
})
const bundledSource = () => [
  { bom: { components: [component('fictional-lib', '1.0-1ubuntu1', 'pkg:deb/ubuntu/fictional-lib@1.0-1ubuntu1')] } },
]
const libraryRules = (overrides = {}) => ({
  release: noble,
  libraries: [
    {
      package: 'fictional-lib',
      reason: 'Sesame gives the library nothing from outside.',
      reviewed: '2026-11-17',
      expires: '2027-02-15',
      ...overrides,
    },
  ],
})
const auditBundled = (advisories, unfixed = libraryRules()) =>
  collectSbomAdvisories(bundledSource(), { query: async () => advisories, unfixed, today: '2026-11-17' })

test('an unfixed Ubuntu advisory below high priority waits under its library rule', async () => {
  const report = await auditBundled([ubuntuAdvisory(), ubuntuAdvisory({ id: 'UBUNTU-CVE-fictional-2', priority: 'low' })])
  assert.equal(report.vulnerable.length, 0)
  assert.deepEqual(report.waiting.map((entry) => entry.ids), [['UBUNTU-CVE-fictional-1', 'UBUNTU-CVE-fictional-2']])
  assert.deepEqual(report.reviewed, [])
  assert.deepEqual(report.unusedLibraries, [])
})

test('an advisory Ubuntu has fixed for the build release fails until the bundle is rebuilt', async () => {
  const report = await auditBundled([ubuntuAdvisory({ fixed: '1.0-1ubuntu2' })])
  assert.deepEqual(report.vulnerable.map((entry) => entry.ids), [['UBUNTU-CVE-fictional-1']])
  assert.deepEqual(report.waiting, [])
})

test('a high, critical or unrated advisory still needs its own entry', async () => {
  for (const priority of ['high', 'critical', 'unknown', null]) {
    const report = await auditBundled([ubuntuAdvisory({ priority })])
    assert.equal(report.vulnerable.length, 1, String(priority))
  }
})

test('an advisory that names only another Ubuntu release or another package does not wait', async () => {
  const other = await auditBundled([ubuntuAdvisory({ release: 'Ubuntu:26.04:LTS' })])
  assert.equal(other.vulnerable.length, 1)
  const pro = await auditBundled([ubuntuAdvisory({ release: 'Ubuntu:Pro:24.04:LTS' })])
  assert.equal(pro.vulnerable.length, 1)
  const renamed = await auditBundled([ubuntuAdvisory({ name: 'another-lib' })])
  assert.equal(renamed.vulnerable.length, 1)
})

test('a fix listed for the build release wins over an unfixed entry for the same package', async () => {
  const advisory = ubuntuAdvisory()
  advisory.affected.push(ubuntuAdvisory({ fixed: '1.0-1ubuntu2' }).affected[0])
  const report = await auditBundled([advisory])
  assert.equal(report.vulnerable.length, 1)
})

test('a library without a rule, an expired rule and a package outside Ubuntu do not wait', async () => {
  const missing = await auditBundled([ubuntuAdvisory()], { release: noble, libraries: [] })
  assert.equal(missing.vulnerable.length, 1)
  const lapsed = await auditBundled([ubuntuAdvisory()], libraryRules({ reviewed: '2026-08-01', expires: '2026-10-01' }))
  assert.equal(lapsed.vulnerable.length, 1)
  assert.deepEqual(lapsed.expiredLibraries.map((rule) => rule.package), ['fictional-lib'])
  assert.equal(
    awaitsUbuntuFix(ubuntuAdvisory(), { name: 'fictional-lib', purl: 'pkg:npm/fictional-lib@1.0.0' }, noble),
    false,
  )
})

test('one advisory outside the rule fails the library even when the others wait', async () => {
  const report = await auditBundled([ubuntuAdvisory(), ubuntuAdvisory({ id: 'UBUNTU-CVE-fictional-9', priority: 'high' })])
  assert.deepEqual(report.vulnerable.map((entry) => entry.ids), [['UBUNTU-CVE-fictional-1', 'UBUNTU-CVE-fictional-9']])
  assert.deepEqual(report.waiting.map((entry) => entry.ids), [['UBUNTU-CVE-fictional-1']])
})

test('a reviewed entry is counted as used even when its library still fails', async () => {
  const rule = { id: 'UBUNTU-CVE-fictional-9', package: 'fictional-lib', reason: 'checked', reviewed: '2026-11-17', expires: '2027-02-15' }
  const report = await collectSbomAdvisories(bundledSource(), {
    query: async () => [{ id: 'UBUNTU-CVE-fictional-9' }, { id: 'UBUNTU-CVE-fictional-10' }],
    allowlist: [rule],
    today: '2026-11-17',
  })
  assert.equal(report.vulnerable.length, 1)
  assert.deepEqual(report.unused, [])
})

test('a library rule needs a release, a reason and an expiry within ninety days', () => {
  const write = (section) => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), 'library-rules-')), 'allowlist.json')
    writeFileSync(file, JSON.stringify({ awaitingUbuntuFix: section, entries: [] }))
    return file
  }
  const rule = libraryRules().libraries[0]
  assert.equal(loadUnfixedLibraryRules(write({ release: noble, libraries: [rule] })).libraries.length, 1)
  assert.throws(() => loadUnfixedLibraryRules(write({ libraries: [rule] })), /Ubuntu release/)
  assert.throws(() => loadUnfixedLibraryRules(write({ release: 'noble', libraries: [rule] })), /Ubuntu release/)
  assert.throws(() => loadUnfixedLibraryRules(write({ release: noble, libraries: [{ ...rule, reason: '' }] })), /reason/)
  assert.throws(
    () => loadUnfixedLibraryRules(write({ release: noble, libraries: [{ ...rule, expires: '2027-06-01' }] })),
    /within 90 days/,
  )
})

test('the shipped library rules name the Ubuntu release that builds the AppImage', () => {
  const { release, libraries } = loadUnfixedLibraryRules()
  const runner = `ubuntu-${release.split(':')[1]}`
  const jobRunner = (file, job) => {
    const workflow = readFileSync(path.join(root, '.github', 'workflows', file), 'utf8')
    const body = workflow.slice(workflow.indexOf(`\n  ${job}:\n`))
    return body.match(/runs-on: (\S+)/)[1]
  }
  assert.equal(jobRunner('ci.yml', 'linux-bundles'), runner)
  const releaseWorkflow = readFileSync(path.join(root, '.github', 'workflows', 'release-linux-early-access.yml'), 'utf8')
  assert.deepEqual([...new Set([...releaseWorkflow.matchAll(/runs-on: (\S+)/g)].map((match) => match[1]))], [runner])
  assert.ok(libraries.length > 0)
  assert.equal(new Set(libraries.map((rule) => rule.package)).size, libraries.length)
  for (const rule of libraries) assert.ok(rule.reason.length > 40, rule.package)
})

test('a crate marked as never compiled is left out of the audit and counted', async () => {
  const unbuilt = (purl) => ({
    ...component('fictional-optional', '3.0.0', purl),
    properties: [{ name: 'sesame:cargo-build', value: 'never-compiled' }],
  })
  const purls = []
  const query = async (purl) => {
    purls.push(purl)
    return [{ id: 'RUSTSEC-fictional-1' }]
  }
  const bom = {
    components: [unbuilt('pkg:cargo/fictional-optional@3.0.0'), component('fictional-clean', '1.0.0', 'pkg:cargo/fictional-clean@1.0.0')],
  }
  const report = await collectSbomAdvisories([{ bom }], { query, today: '2026-11-17' })
  assert.deepEqual(purls, ['pkg:cargo/fictional-clean@1.0.0'])
  assert.equal(report.neverCompiled, 1)
  assert.equal(report.skipped, 0)
  assert.deepEqual(report.vulnerable.map((entry) => entry.name), ['fictional-clean'])
})

test('the never compiled mark does not hide a package outside cargo', async () => {
  const bom = {
    components: [
      {
        ...component('fictional-npm', '1.0.0', 'pkg:npm/fictional-npm@1.0.0'),
        properties: [{ name: 'sesame:cargo-build', value: 'never-compiled' }],
      },
    ],
  }
  const report = await collectSbomAdvisories([{ bom }], { query: async () => [{ id: 'GHSA-fictional-2' }], today: '2026-11-17' })
  assert.equal(report.vulnerable.length, 1)
  assert.equal(report.neverCompiled, 0)
})

const withdrawnSource = () => [
  { label: 'locked.cdx.json', bom: { components: [component('fictional-merge', '1.0.0', 'pkg:npm/fictional-merge@1.0.0')] } },
]
const auditWithdrawn = (advisories) =>
  collectSbomAdvisories(withdrawnSource(), {
    query: async () => advisories,
    today: '2026-11-17',
    now: Date.parse('2026-11-17T12:00:00Z'),
  })

test('an advisory its publisher withdrew is left out and counted', async () => {
  const report = await auditWithdrawn([{ id: 'GHSA-fictional-gone', withdrawn: '2026-11-16T18:55:38Z' }])
  assert.equal(report.vulnerable.length, 0)
  assert.deepEqual(report.withdrawn.map((entry) => [entry.label, entry.name, entry.ids]), [
    ['locked.cdx.json', 'fictional-merge', ['GHSA-fictional-gone']],
  ])
  const single = await collectAdvisories(withdrawnSource()[0].bom, {
    query: async () => [{ id: 'GHSA-fictional-gone', withdrawn: '2026-11-16T18:55:38.123456789Z' }],
    now: Date.parse('2026-11-17T12:00:00Z'),
  })
  assert.equal(single.vulnerable.length, 0)
  assert.equal(single.withdrawn.length, 1)
})

test('an advisory without a withdrawn time still fails beside a withdrawn one', async () => {
  const report = await auditWithdrawn([
    { id: 'GHSA-fictional-gone', withdrawn: '2026-11-16T18:55:38Z' },
    { id: 'GHSA-fictional-live' },
  ])
  assert.deepEqual(report.vulnerable.map((entry) => entry.ids), [['GHSA-fictional-live']])
  assert.deepEqual(report.withdrawn.map((entry) => entry.ids), [['GHSA-fictional-gone']])
})

test('a withdrawn field that is not a valid past time does not withdraw the advisory', async () => {
  for (const withdrawn of [null, '', 'yes', true, 1763319338, '2026-11-16', '2026-02-30T00:00:00Z', '2026-11-16T25:00:00Z', '2026-11-16T18:55:38+02:00', '2026-11-18T00:00:00Z']) {
    const report = await auditWithdrawn([{ id: 'GHSA-fictional-live', withdrawn }])
    assert.equal(report.vulnerable.length, 1, JSON.stringify(withdrawn))
    assert.equal(report.withdrawn.length, 0, JSON.stringify(withdrawn))
  }
  assert.equal(isWithdrawn({ withdrawn: '2026-11-16T18:55:38Z' }, Date.parse('2026-11-17T00:00:00Z')), true)
  assert.equal(isWithdrawn({}, Date.parse('2026-11-17T00:00:00Z')), false)
})

const crate = (role, { name = 'fictional-crate', pulledInBy = 'fictional-framework' } = {}) => ({
  ...component(name, '5.0.0', `pkg:cargo/${name}@5.0.0`),
  properties: [
    ...(role === undefined ? [] : [].concat(role).map((value) => ({ name: 'sesame:cargo-dependency', value }))),
    ...(pulledInBy ? [{ name: 'sesame:cargo-pulled-in-by', value: pulledInBy }] : []),
  ],
})
const unmaintainedNotice = ({ id = 'RUSTSEC-2026-9001', name = 'fictional-crate', facts = {}, effects = {}, ...rest } = {}) => ({
  id,
  affected: [
    {
      package: { ecosystem: 'crates.io', name, purl: `pkg:cargo/${name}` },
      ecosystem_specific: { affects: { arch: [], os: [], functions: [] }, affected_functions: null, ...effects },
      database_specific: { categories: [], cvss: null, informational: 'unmaintained', ...facts },
    },
  ],
  database_specific: { license: 'CC0-1.0' },
  ...rest,
})
const auditCrate = (target, advisories) =>
  collectSbomAdvisories([{ bom: { components: [target] } }], { query: async () => advisories, today: '2026-11-17' })

test('an unmaintained notice for a crate that only arrives through other crates is a notice', async () => {
  const report = await auditCrate(crate('transitive'), [unmaintainedNotice()])
  assert.equal(report.vulnerable.length, 0)
  assert.deepEqual(report.unmaintained.map((entry) => [entry.name, entry.ids, entry.pulledInBy]), [
    ['fictional-crate', ['RUSTSEC-2026-9001'], 'fictional-framework'],
  ])
  assert.deepEqual(report.reviewed, [])
})

test('an unmaintained notice fails for a direct, unmarked or ambiguously marked crate', async () => {
  for (const role of ['direct', undefined, 'unknown', ['transitive', 'direct'], '']) {
    const report = await auditCrate(crate(role), [unmaintainedNotice()])
    assert.equal(report.vulnerable.length, 1, JSON.stringify(role))
    assert.deepEqual(report.unmaintained, [], JSON.stringify(role))
  }
  const npm = { ...crate('transitive'), purl: 'pkg:npm/fictional-crate@5.0.0' }
  assert.equal((await auditCrate(npm, [unmaintainedNotice()])).vulnerable.length, 1)
})

test('a notice that carries anything beyond unmaintained still fails for a transitive crate', async () => {
  const cases = {
    unsound: unmaintainedNotice({ facts: { informational: 'unsound' } }),
    notice: unmaintainedNotice({ facts: { informational: 'notice' } }),
    vulnerability: unmaintainedNotice({ facts: { informational: null } }),
    'no informational kind': unmaintainedNotice({ facts: { informational: undefined } }),
    cvss: unmaintainedNotice({ facts: { cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }),
    category: unmaintainedNotice({ facts: { categories: ['memory-corruption'] } }),
    'affected functions': unmaintainedNotice({ effects: { affected_functions: ['fictional_crate::parse'] } }),
    'affects functions': unmaintainedNotice({ effects: { affects: { functions: ['fictional_crate::parse'] } } }),
    severity: unmaintainedNotice({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }] }),
    alias: unmaintainedNotice({ aliases: ['CVE-2026-0001'] }),
    cwe: unmaintainedNotice({ database_specific: { cwe_ids: ['CWE-400'] } }),
    'github advisory': unmaintainedNotice({ id: 'GHSA-fictional-0001' }),
    'another crate': unmaintainedNotice({ name: 'another-crate' }),
    'no affected entry': { ...unmaintainedNotice(), affected: [] },
  }
  for (const [label, advisory] of Object.entries(cases)) {
    const report = await auditCrate(crate('transitive'), [advisory])
    assert.equal(report.vulnerable.length, 1, label)
    assert.equal(onlyUnmaintained(advisory, crate('transitive')), false, label)
  }
  const mixed = await auditCrate(crate('transitive'), [unmaintainedNotice(), unmaintainedNotice({ id: 'RUSTSEC-2026-9002', facts: { informational: 'unsound' } })])
  assert.deepEqual(mixed.vulnerable.map((entry) => entry.ids), [['RUSTSEC-2026-9001', 'RUSTSEC-2026-9002']])
})

const npmPackage = (scope, name = 'fictional-glob') => ({ ...component(name, '4.0.0', `pkg:npm/${name}@4.0.0`), ...(scope === undefined ? {} : { scope }) })
const githubAdvisory = (cweIds, id = 'GHSA-fictional-glob') => ({
  id,
  affected: [{ package: { ecosystem: 'npm', name: 'fictional-glob' } }],
  database_specific: cweIds === undefined ? { severity: 'HIGH' } : { severity: 'HIGH', cwe_ids: cweIds },
})
const auditPackage = (target, advisories) =>
  collectSbomAdvisories([{ bom: { components: [target] } }], { query: async () => advisories, today: '2026-11-17' })

test('resource exhaustion in an npm package that never ships is a notice', async () => {
  for (const cweIds of [['CWE-1333'], ['CWE-400'], ['CWE-405'], ['CWE-407'], ['CWE-770'], ['CWE-834'], ['CWE-1333', 'CWE-400']]) {
    const report = await auditPackage(npmPackage('excluded'), [githubAdvisory(cweIds)])
    assert.equal(report.vulnerable.length, 0, cweIds.join())
    assert.deepEqual(report.buildTools.map((entry) => [entry.name, entry.ids, entry.weaknesses]), [
      ['fictional-glob', ['GHSA-fictional-glob'], [...cweIds].sort()],
    ])
    assert.deepEqual(report.reviewed, [])
  }
})

test('any other weakness or a missing weakness list in a build tool still fails', async () => {
  for (const cweIds of [undefined, null, [], 'CWE-1333', ['CWE-94'], ['CWE-22'], ['CWE-1321'], ['CWE-506'], ['CWE-1333', 'CWE-94'], ['cwe-1333']]) {
    const report = await auditPackage(npmPackage('excluded'), [githubAdvisory(cweIds)])
    assert.equal(report.vulnerable.length, 1, JSON.stringify(cweIds))
    assert.deepEqual(report.buildTools, [], JSON.stringify(cweIds))
  }
  const malware = await auditPackage(npmPackage('excluded'), [{ id: 'MAL-2026-0001', affected: [{ package: { ecosystem: 'npm', name: 'fictional-glob' } }] }])
  assert.equal(malware.vulnerable.length, 1)
  const mixed = await auditPackage(npmPackage('excluded'), [githubAdvisory(['CWE-1333']), githubAdvisory(['CWE-78'], 'GHSA-fictional-exec')])
  assert.deepEqual(mixed.vulnerable.map((entry) => entry.ids), [['GHSA-fictional-glob', 'GHSA-fictional-exec']])
})

test('resource exhaustion fails in a package that ships or whose shipped state is unknown', async () => {
  for (const scope of ['required', 'optional', undefined, 'EXCLUDED']) {
    const report = await auditPackage(npmPackage(scope), [githubAdvisory(['CWE-1333'])])
    assert.equal(report.vulnerable.length, 1, String(scope))
  }
  const cargo = { ...component('fictional-glob', '4.0.0', 'pkg:cargo/fictional-glob@4.0.0'), scope: 'excluded' }
  assert.equal((await auditPackage(cargo, [githubAdvisory(['CWE-1333'])])).vulnerable.length, 1)
  const bundled = { ...component('fictional-glob', '4.0.0', 'pkg:deb/ubuntu/fictional-glob@4.0.0'), scope: 'excluded' }
  assert.equal((await auditPackage(bundled, [githubAdvisory(['CWE-1333'])])).vulnerable.length, 1)
})

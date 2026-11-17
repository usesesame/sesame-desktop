import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  cargoFindings,
  evaluateFindings,
  loadExceptions,
  npmFindings,
  npmShippedState,
  validateExceptions,
} from './audit-dependencies.mjs'

const root = path.resolve(import.meta.dirname, '..')
const today = '2026-10-24'

const exception = (overrides = {}) => ({
  id: 'GHSA-xq3m-2v4x-88gg',
  package: 'example-parser',
  reason: 'The parser only reads files the build writes itself.',
  reviewed: '2026-10-20',
  expires: '2026-11-19',
  ...overrides,
})

const npmReport = (via) => ({ auditReportVersion: 2, vulnerabilities: { 'example-parser': { name: 'example-parser', via } } })

const advisory = (overrides = {}) => ({
  source: 1100001,
  name: 'example-parser',
  title: 'Example parser reads past its buffer',
  url: 'https://github.com/advisories/GHSA-xq3m-2v4x-88gg',
  severity: 'high',
  ...overrides,
})

test('the committed exceptions file is valid today', () => {
  assert.doesNotThrow(() => loadExceptions(new Date().toISOString().slice(0, 10)))
})

test('the supply chain job audits npm and Rust through the exceptions gate', () => {
  const workflow = readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /run: node tools\/audit-dependencies\.mjs$/m)
  assert.doesNotMatch(workflow, /run: npm audit\b/, 'a bare npm audit ignores the reviewed exceptions')
  assert.doesNotMatch(workflow, /run: cargo audit\b/, 'a bare cargo audit ignores the reviewed exceptions')
})

test('an exception must be well formed', () => {
  assert.throws(() => validateExceptions({}, today), /"entries" array/)
  assert.throws(() => validateExceptions({ entries: [exception({ id: 'CVE-2026-1' })] }, today), /GHSA or RUSTSEC/)
  assert.throws(() => validateExceptions({ entries: [exception({ reason: ' ' })] }, today), /needs a reason/)
  assert.throws(() => validateExceptions({ entries: [exception({ expires: '2026-02-30' })] }, today), /YYYY-MM-DD/)
  assert.throws(() => validateExceptions({ entries: [{ ...exception(), note: 'extra' }] }, today), /exactly an id/)
  assert.throws(() => validateExceptions({ entries: [exception(), exception()] }, today), /listed twice/)
})

test('an exception lasts at most 30 days from its review and fails once it expires', () => {
  assert.doesNotThrow(() => validateExceptions({ entries: [exception({ reviewed: '2026-10-24', expires: '2026-11-23' })] }, today))
  assert.throws(() => validateExceptions({ entries: [exception({ reviewed: '2026-10-24', expires: '2026-11-24' })] }, today), /within 30 days/)
  assert.throws(() => validateExceptions({ entries: [exception({ reviewed: '2026-10-25', expires: '2026-11-01' })] }, today), /after today/)
  assert.throws(() => validateExceptions({ entries: [exception({ reviewed: '2026-09-30', expires: '2026-10-23' })] }, today), /expired on 2026-10-23/)
  assert.doesNotThrow(() => validateExceptions({ entries: [exception({ reviewed: '2026-09-30', expires: '2026-10-24' })] }, today))
})

test('npm advisories at high and critical fail and lower ones do not', () => {
  const findings = npmFindings(npmReport([advisory(), advisory({ severity: 'moderate', url: 'https://github.com/advisories/GHSA-2222-3333-4444' }), 'example-parent']))
  assert.deepEqual(findings.map(({ id, severity }) => [id, severity]), [['GHSA-xq3m-2v4x-88gg', 'high']])
  assert.equal(npmFindings(npmReport([advisory({ severity: 'critical' })]))[0].severity, 'critical')
})

test('a failed or empty audit fails closed', () => {
  assert.throws(() => npmFindings({ error: { code: 'ENOAUDIT', summary: 'the registry is unreachable' } }), /the registry is unreachable/)
  assert.throws(() => npmFindings({}), /did not return a report/)
  assert.throws(() => cargoFindings({}), /did not return a report/)
})

test('an exception accepts only the advisory and package it names', () => {
  const findings = [
    ...npmFindings(npmReport([advisory()])),
    ...cargoFindings({ vulnerabilities: { list: [{ advisory: { id: 'RUSTSEC-2026-0001', title: 'Example crate' }, package: { name: 'example-crate' } }] } }),
  ]
  const result = evaluateFindings(findings, [
    exception(),
    exception({ id: 'RUSTSEC-2026-0001', package: 'another-crate' }),
  ])
  assert.deepEqual(result.accepted.map(({ id }) => id), ['GHSA-xq3m-2v4x-88gg'])
  assert.deepEqual(result.blocking.map(({ id, package: name }) => [id, name]), [['RUSTSEC-2026-0001', 'example-crate']])
  assert.deepEqual(result.unused.map(({ package: name }) => name), ['another-crate'])
})

test('an npm advisory without a GHSA identifier can never be accepted', () => {
  const findings = npmFindings(npmReport([advisory({ url: 'https://example.invalid/advisory' })]))
  assert.equal(findings[0].id, 'npm advisory 1100001')
  assert.equal(evaluateFindings(findings, [exception()]).blocking.length, 1)
})

const globReport = (cwe, name = 'example-glob') =>
  npmReport([advisory({ name, url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf', ...(cwe === undefined ? {} : { cwe }) })])
const devLock = {
  packages: {
    '': { name: 'example-app' },
    'node_modules/example-glob': { version: '4.0.7', dev: true },
    'node_modules/example-bundler/node_modules/example-glob': { version: '2.3.1', dev: true },
    'node_modules/example-runtime': { version: '1.0.0' },
    'node_modules/example-split': { version: '1.0.0', dev: true },
    'node_modules/example-tool/node_modules/example-split': { version: '0.9.0', devOptional: true },
    'node_modules/example-alias': { name: 'example-real', version: '3.0.0', dev: true },
  },
}
const buildOnly = npmShippedState(devLock, new Set(['example-ui']))

test('resource exhaustion in an npm package that never ships is a notice', () => {
  for (const cwe of [['CWE-1333'], ['CWE-400', 'CWE-405'], ['CWE-407'], ['CWE-770'], ['CWE-834']]) {
    const result = evaluateFindings(npmFindings(globReport(cwe)), [], { ships: buildOnly })
    assert.deepEqual(result.blocking, [], cwe.join())
    assert.deepEqual(result.buildTools.map(({ package: name, cwe: weaknesses }) => [name, weaknesses]), [['example-glob', cwe]])
  }
  assert.equal(buildOnly('example-real'), false)
})

test('a build tool advisory with another or no weakness still fails', () => {
  for (const cwe of [undefined, [], ['CWE-94'], ['CWE-22'], ['CWE-1321'], ['CWE-506'], ['CWE-1333', 'CWE-78'], 'CWE-1333']) {
    const result = evaluateFindings(npmFindings(globReport(cwe)), [], { ships: buildOnly })
    assert.equal(result.blocking.length, 1, JSON.stringify(cwe))
    assert.deepEqual(result.buildTools, [], JSON.stringify(cwe))
  }
})

test('resource exhaustion fails in a package that ships or whose shipped state is unknown', () => {
  const blocked = (name, ships) => evaluateFindings(npmFindings(globReport(['CWE-1333'], name)), [], { ships }).blocking.length
  assert.equal(blocked('example-runtime', buildOnly), 1, 'a production copy ships')
  assert.equal(blocked('example-split', buildOnly), 1, 'one copy that is not dev only ships')
  assert.equal(blocked('example-ui', npmShippedState({ packages: { 'node_modules/example-ui': { dev: true } } }, new Set(['example-ui']))), 1, 'the bundle lists it')
  assert.equal(blocked('example-missing', buildOnly), 1, 'the lock file does not list it')
  assert.equal(blocked('example-glob', npmShippedState(devLock, null)), 1, 'the shipped list is missing')
  assert.equal(blocked('example-glob', undefined), 1, 'no shipped state was given')
  const cargo = cargoFindings({ vulnerabilities: { list: [{ advisory: { id: 'RUSTSEC-2026-0001' }, package: { name: 'example-glob' } }] } })
  assert.equal(evaluateFindings(cargo.map((finding) => ({ ...finding, cwe: ['CWE-1333'] })), [], { ships: buildOnly }).blocking.length, 1)
})

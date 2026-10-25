import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  cargoFindings,
  evaluateFindings,
  loadExceptions,
  npmFindings,
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

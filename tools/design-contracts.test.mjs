import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { TYPE_ALLOWLIST, findLiteralTypeDeclarations } from './design-contracts.mjs'

const repository = process.cwd()
const appCss = path.join(repository, 'src', 'app.css')

test('a literal font size, weight, or shorthand is a violation', () => {
  const violations = findLiteralTypeDeclarations([
    { path: 'fixture.css', text: '.card { font-size: 14px; }\n' },
    { path: 'fixture.css', text: '.card strong { font-weight: 600; }\n' },
    { path: 'fixture.css', text: '.card kbd { font: 600 10px/1 sans-serif; }\n' },
  ])
  assert.deepEqual(violations.map((entry) => entry.property), ['font-size', 'font-weight', 'font'])
})

test('scale tokens and keywords are accepted', () => {
  const violations = findLiteralTypeDeclarations([
    { path: 'fixture.css', text: '.card { font-size: var(--type-2); font-weight: var(--weight-medium); }\n' },
    { path: 'fixture.css', text: '.card button { font: inherit; font-weight: inherit; }\n' },
  ])
  assert.deepEqual(violations, [])
})

test('the documented allowlist covers the wordmark and glyphs only', () => {
  for (const entry of TYPE_ALLOWLIST) {
    assert.match(entry.reason, /\S/, `${entry.selector} has no documented reason`)
  }
  const violations = findLiteralTypeDeclarations([
    { path: 'fixture.css', text: '.brand { font-size: 23px; }\n.sesame-mark { font-size: 20px; }\n.empty-icon.size-md { font-size: 25px; }\n' },
  ])
  assert.deepEqual(violations, [])
})

test('the allowlist matches the selector itself, not a substring or a selector list', () => {
  const violations = findLiteralTypeDeclarations([
    { path: 'fixture.css', text: '.brandish { font-size: 14px; }\n' },
    { path: 'fixture.css', text: '.brand, .entry-title { font-size: 14px; }\n' },
    { path: 'fixture.css', text: '.sidebar .brand { font-size: 19px; }\n' },
  ])
  assert.deepEqual(violations.map((entry) => entry.selector), ['.brandish', '.brand, .entry-title'])
})

test('comments cannot hide or invent a declaration', () => {
  const violations = findLiteralTypeDeclarations([
    { path: 'fixture.css', text: '.card { /* note */ font-size: 14px; }\n' },
    { path: 'fixture.css', text: '/* .card { font-size: 14px; } */\n.card { font-size: var(--type-1); }\n' },
  ])
  assert.deepEqual(violations.map((entry) => entry.value), ['14px'])
})

test('a numeric weight with a priority suffix is still a violation', () => {
  const violations = findLiteralTypeDeclarations([
    { path: 'fixture.css', text: '.card { font-weight: 600 !important; }\n' },
  ])
  assert.deepEqual(violations.map((entry) => entry.property), ['font-weight'])
})

test('the desktop stylesheet passes and a planted literal fails', () => {
  const real = readFileSync(appCss, 'utf8')
  assert.deepEqual(findLiteralTypeDeclarations([{ path: 'src/app.css', text: real }]), [])
  const planted = real.replace('.entry-title strong { overflow: hidden;', '.entry-title strong { font-size: 14px; overflow: hidden;')
  assert.notEqual(planted, real)
  const violations = findLiteralTypeDeclarations([{ path: 'src/app.css', text: planted }])
  assert.equal(violations.length, 1)
  assert.equal(violations[0].value, '14px')
})

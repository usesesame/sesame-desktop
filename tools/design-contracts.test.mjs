import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { TYPE_ALLOWLIST, block, contrastRatio, declarations, evaluateContrast, findLiteralRadiusDeclarations, findLiteralTypeDeclarations } from './design-contracts.mjs'

const repository = process.cwd()
const appCss = path.join(repository, 'src', 'app.css')
const tokens = path.join(repository, 'design', 'tokens.css')

function palettes() {
  const css = readFileSync(tokens, 'utf8')
  const light = declarations(block(css, /^:root \{/m))
  const dark = declarations(block(css, /^:root\[data-theme="dark"\] \{/m))
  return { css, light, dark }
}

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

test('contrast ratio uses the WCAG relative luminance', () => {
  assert.equal(contrastRatio('#000000', '#ffffff').toFixed(2), '21.00')
  assert.equal(contrastRatio('#ffffff', '#ffffff'), 1)
})

test('the real tokens clear every named contrast pair in both themes', () => {
  const { light, dark } = palettes()
  assert.deepEqual(evaluateContrast('light', new Map(light)), [])
  assert.deepEqual(evaluateContrast('dark', new Map([...light, ...dark])), [])
})

test('lowering a measured token fails the contract', () => {
  const { css } = palettes()
  const lowered = css.replace('--text-muted: #5d695e;', '--text-muted: #9aa595;')
  assert.notEqual(lowered, css)
  const violations = evaluateContrast('light', new Map(declarations(block(lowered, /^:root \{/m))))
  assert.deepEqual(violations.map((entry) => entry.name), ['muted text on background', 'muted text on surface'])
})

test('a literal corner radius is a violation unless the allowlist covers it', () => {
  const violations = findLiteralRadiusDeclarations([{ path: 'fixture.css', text: '.card { border-radius: 5px; }\n' }])
  assert.equal(violations.length, 1)
  assert.deepEqual(
    findLiteralRadiusDeclarations([
      { path: 'fixture.css', text: '.card { border-radius: var(--radius-md); }\n.circle { border-radius: 50%; }\n.flat { border-radius: 0; }\n' },
    ]),
    [],
  )
  assert.deepEqual(
    findLiteralRadiusDeclarations(
      [{ path: 'fixture.css', text: '.special { border-radius: 7px; }\n' }],
      [{ selector: '.special', reason: 'fixture exemption' }],
    ),
    [],
  )
})

test('the desktop stylesheet has no literal radius and a planted one fails', () => {
  const real = readFileSync(appCss, 'utf8')
  assert.deepEqual(findLiteralRadiusDeclarations([{ path: 'src/app.css', text: real }]), [])
  const planted = real.replace('.empty-vault h3 {', '.empty-vault h3 { border-radius: 6px;')
  assert.notEqual(planted, real)
  const violations = findLiteralRadiusDeclarations([{ path: 'src/app.css', text: planted }])
  assert.equal(violations.length, 1)
  assert.equal(violations[0].value, '6px')
})

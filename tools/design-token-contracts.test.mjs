// An undefined var(--token) with no fallback makes the declaration invalid and CSS resolves it to unset, silently.

import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

function defined(text) {
  return new Set([...text.matchAll(/(--[a-z0-9-]+)\s*:/g)].map((m) => m[1]))
}

function usedWithoutFallback(text) {
  return [...text.matchAll(/var\(\s*(--[a-z0-9-]+)\s*\)/g)].map((m) => m[1])
}

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    if (['node_modules', 'dist', 'test-results'].includes(name)) return []
    const full = join(dir, name)
    if (statSync(full).isDirectory()) return sourceFiles(full)
    return /\.(css|svelte)$/.test(name) ? [full] : []
  })
}

const shared = defined(readFileSync(join(root, 'design', 'tokens.css'), 'utf8'))

const surfaces = [
  { name: 'desktop app', dir: 'src' },
  { name: 'website', dir: 'website/src' },
  { name: 'account portal', dir: 'account/src' },
  { name: 'admin app', dir: 'admin/src' },
  { name: 'browser extension', dir: 'extensions/sesame/src' },
]

test('design/tokens.css defines the shared scales every surface relies on', () => {
  for (const token of [
    '--font-ui',
    '--font-display',
    '--font-code',
    '--radius-sm',
    '--radius-md',
    '--radius-lg',
    '--radius-pill',
    '--space-1',
    '--space-7',
    '--type-1',
    '--type-6',
    '--accent',
    '--gold',
    '--danger',
    '--surface',
    '--border',
    '--text',
  ]) {
    assert.ok(shared.has(token), `design/tokens.css must define ${token}`)
  }
})

for (const surface of surfaces) {
  test(`${surface.name} uses no undefined custom property`, () => {
    const files = sourceFiles(join(root, surface.dir))

    const local = new Set()
    for (const file of files) for (const token of defined(readFileSync(file, 'utf8'))) local.add(token)

    const problems = []
    for (const file of files) {
      const text = readFileSync(file, 'utf8')
      for (const token of usedWithoutFallback(text)) {
        if (!shared.has(token) && !local.has(token)) {
          problems.push(`${file.slice(root.length + 1).replaceAll('\\', '/')} uses ${token}`)
        }
      }
    }

    assert.deepEqual(
      problems,
      [],
      `${surface.name} references custom properties that nothing defines, so those declarations silently do not apply:\n  ${problems.join('\n  ')}`,
    )
  })
}

test('design/tokens.css sets the base typography for every surface', () => {
  const css = readFileSync(join(root, 'design', 'tokens.css'), 'utf8')
  const base = css.slice(css.search(/^:root \{/m), css.indexOf('}', css.search(/^:root \{/m)))
  assert.match(base, /font-family:\s*var\(--font-ui\)/, ':root must set font-family to var(--font-ui)')
  assert.match(base, /background:\s*var\(--bg\)/, ':root must set background to var(--bg)')
  assert.match(base, /color:\s*var\(--text\)/, ':root must set color to var(--text)')
})

test('no surface paints hardcoded white on a themed background', () => {
  const offenders = []
  for (const surface of surfaces) {
    for (const file of sourceFiles(join(root, surface.dir))) {
      const text = readFileSync(file, 'utf8')
      for (const line of text.split('\n')) {
        if (!/color:\s*(#fff\b|#ffffff\b|white\b)/i.test(line)) continue
        if (!/background(-color)?:\s*var\(--/.test(line)) continue
        offenders.push(`${file.slice(root.length + 1).replaceAll('\\', '/')}: ${line.trim().slice(0, 90)}`)
      }
    }
  }
  assert.deepEqual(offenders, [], `hardcoded white over a themed background:\n  ${offenders.join('\n  ')}`)
})

function luminance(hex) {
  const value = hex.replace('#', '')
  const [r, g, b] = [0, 2, 4]
    .map((i) => parseInt(value.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function tokenBlock(css, pattern) {
  const start = css.search(pattern)
  if (start < 0) return ''
  const open = css.indexOf('{', start)
  let depth = 0
  for (let i = open; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1
    else if (css[i] === '}') {
      depth -= 1
      if (depth === 0) return css.slice(open + 1, i)
    }
  }
  return ''
}

test('the surface ladder climbs in the same order in both themes', () => {
  const css = readFileSync(join(root, 'design', 'tokens.css'), 'utf8')
  const ladder = ['bg', 'surface-inset', 'surface-3', 'surface-2', 'surface']

  for (const [name, pattern] of [
    ['light', /^:root \{/m],
    ['dark', /^:root\[data-theme="dark"\] \{/m],
  ]) {
    const block = tokenBlock(css, pattern)
    const steps = ladder.map((token) => {
      const match = block.match(new RegExp(`--${token}:\\s*(#[0-9a-fA-F]{6})\\s*;`))
      assert.ok(match, `${name} palette is missing --${token}`)
      return { token, hex: match[1], lum: luminance(match[1]) }
    })
    for (let i = 1; i < steps.length; i += 1) {
      assert.ok(
        steps[i].lum > steps[i - 1].lum,
        `${name}: --${steps[i].token} (${steps[i].hex}) must sit above --${steps[i - 1].token} (${steps[i - 1].hex}) in the elevation ladder, but it is darker or equal`,
      )
    }
  }
})

test('selected controls all use the one shared treatment', () => {
  const files = [
    ['src', 'app.css'],
    ['website', 'src', 'site.css'],
  ]
  const offenders = []
  for (const parts of files) {
    const source = readFileSync(join(root, ...parts), 'utf8')
    for (const line of source.split('\n')) {
      if (!/\.(active|selected)\b[^{]*\{/.test(line)) continue
      if (!/background|box-shadow/.test(line)) continue
      if (line.includes('--control-active-bg')) continue
      if (/^\s*\.(sidebar|lock-button)/.test(line) && line.includes('--sidebar-active-layer')) continue
      if (/::after|::before/.test(line)) continue
      if (/:not\(\.(active|selected)\)/.test(line)) continue
      if (/switch|toggle-check|favourite/.test(line)) continue
      offenders.push(`${parts.join('/')}: ${line.trim().slice(0, 96)}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these active states do not use --control-active-bg:\n  ${offenders.join('\n  ')}`,
  )
})

test('every surface spells the wordmark the way design/tokens.css does', () => {
  for (const parts of [
    ['website', 'src', 'Site.svelte'],
    ['admin', 'src', 'App.svelte'],
    ['src', 'lib', 'ui', 'Sidebar.svelte'],
    ['src', 'lib', 'ui', 'AppChrome.svelte'],
    ['src', 'lib', 'ui', 'RecoveryKitScreen.svelte'],
  ]) {
    const source = readFileSync(join(root, ...parts), 'utf8')
    assert.ok(
      !/>\s*sesame\s*</.test(source),
      `${parts.join('/')} renders the wordmark lowercase; design/tokens.css says Sesame`,
    )
  }
})

test('the browser overlay carries its own tokens because it cannot inherit them', () => {
  const overlay = readFileSync(join(root, 'extensions/sesame/src/content/overlay.ts'), 'utf8')
  assert.match(overlay, /import \{ OVERLAY_TOKEN_CSS \} from '\.\/overlay-tokens'/)
  assert.match(overlay, /\$\{OVERLAY_TOKEN_CSS\}/)
  assert.doesNotMatch(
    overlay,
    /#[0-9a-fA-F]{6}/,
    'overlay.ts must not hardcode a colour. Add the token to design/tokens.css and run `npm run design:tokens:sync`.',
  )
})

test('every field focus state resolves to the shared --field-* treatment', () => {
  const surfaces = [
    ['src', 'app.css'],
    ['website', 'src', 'site.css'],
    ['admin', 'src', 'app.css'],
  ]
  const banned = [
    [/border-color:\s*var\(--border-input-focus\)/, 'border-color: var(--border-input-focus)'],
    [/border-color:\s*var\(--accent-link\)/, 'border-color: var(--accent-link)'],
    [/box-shadow:\s*var\(--focus-glow\)/, 'box-shadow: var(--focus-glow)'],
    [/outline:\s*\d+px solid/, 'a solid outline'],
  ]

  const offenders = []
  for (const parts of surfaces) {
    const source = readFileSync(join(root, ...parts), 'utf8')
    for (const line of source.split('\n')) {
      if (!/:focus/.test(line)) continue
      if (!/\b(input|textarea|select|search-box)\b/.test(line)) continue
      for (const [pattern, name] of banned) {
        if (pattern.test(line)) offenders.push(`${parts.join('/')}: ${name} in ${line.trim().slice(0, 90)}`)
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these field focus rules bypass the shared treatment:\n  ${offenders.join('\n  ')}`,
  )
})

test('the retired focus tokens are gone so no surface can reach for them again', () => {
  const tokens = readFileSync(join(root, 'design', 'tokens.css'), 'utf8')
  for (const name of ['--border-input-focus', '--focus-glow', '--field-border-focus']) {
    assert.ok(
      !tokens.includes(`${name}:`),
      `${name} is declared again. Focus is --field-ring alone; hover is --field-border-hover.`,
    )
  }
  assert.match(tokens, /--field-ring:/)
  assert.match(tokens, /--field-border-hover:/)
})

test('focus is the gold halo alone, on every field and every surface', () => {
  const css = readFileSync(join(root, 'design', 'tokens.css'), 'utf8')

  function block(header) {
    const start = css.indexOf(header)
    assert.notEqual(start, -1, `tokens.css no longer has a ${header} block`)
    let depth = 0
    let end = start
    for (let i = css.indexOf('{', start); i < css.length; i += 1) {
      if (css[i] === '{') depth += 1
      else if (css[i] === '}') { depth -= 1; if (depth === 0) { end = i; break } }
    }
    const map = new Map()
    for (const m of css.slice(start, end).matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
      map.set(m[1], m[2].trim())
    }
    return map
  }

  const light = block(':root {')

  // The gold halo alone is nowhere near 3:1, a recorded deviation from WCAG 2.2 SC 1.4.11. See the Fields block in design/tokens.css.
  assert.match(light.get('--field-ring'), /var\(--gold\)/, '--field-ring no longer draws the gold halo')
  assert.doesNotMatch(
    light.get('--field-ring'),
    /0 0 0 1px/,
    'a solid 1px layer is back inside --field-ring, which is the doubled edge this treatment removed',
  )

  for (const surface of [['src', 'app.css'], ['website', 'src', 'site.css'], ['admin', 'src', 'app.css']]) {
    const name = surface.join('/')
    const css = readFileSync(join(root, ...surface), 'utf8')
    assert.doesNotMatch(
      css,
      /border-color: var\(--field-border-focus\)/,
      `${name} recolours a field border on focus again, which is the hard bright ring the halo replaced`,
    )
    for (const [index, line] of css.split('\n').entries()) {
      if (!/^\S[^{]*:focus(-visible|-within)?\b[^{]*\{/.test(line)) continue
      if (!/box-shadow:\s*none/.test(line)) continue
      assert.match(
        line,
        /input|\.pin-entry/,
        `${name}:${index + 1} removes the focus halo from a field without being the inner-input silencer, so that field marks focus with nothing`,
      )
    }
  }
})

test('a field that rings its wrapper silences the input inside it', () => {
  for (const surface of [['src', 'app.css'], ['website', 'src', 'site.css'], ['admin', 'src', 'app.css']]) {
    const name = surface.join('/')
    const css = readFileSync(join(root, ...surface), 'utf8')
    const lines = css.split('\n')
    for (const [index, line] of lines.entries()) {
      if (!/box-shadow:[^;]*var\(--field-ring(-danger)?\)/.test(line)) continue
      const wrapper = line.match(/^(\S+?)(:focus-within|:has\(input:focus)/)
      if (!wrapper) continue
      const base = wrapper[1]
      const silenced = lines.some(
        (candidate) =>
          candidate !== line &&
          candidate.includes(base) &&
          /:focus(-visible)?\b/.test(candidate) &&
          /box-shadow: none/.test(candidate),
      )
      assert.ok(
        silenced,
        `${name}:${index + 1} rings ${base} on focus without a rule setting box-shadow: none on the input inside it, so the field draws two concentric halos`,
      )
    }
  }
})

test('the 2FA button is the same height as the button beside it', () => {
  const css = readFileSync(join(root, 'src', 'app.css'), 'utf8')
  const declaration = (selector, property) => {
    const line = css.split('\n').find((candidate) => candidate.startsWith(selector + ' {'))
    assert.ok(line, `${selector} is no longer a single-line rule this test can read`)
    const body = line.match(/\{([^}]*)\}/)
    assert.ok(body, `${selector} is no longer a single-line rule this test can read`)
    const found = body[1].match(new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;]+)`))
    assert.ok(found, `${selector} no longer sets ${property}`)
    return found[1].trim()
  }
  const px = (value) => {
    const found = value.match(/(-?[\d.]+)px/)
    assert.ok(found, `expected a pixel length, got ${value}`)
    return Number(found[1])
  }

  const shared = '.site-action, .totp-action'
  const minHeight = px(declaration(shared, 'min-height'))
  const padding = px(declaration(shared, 'padding'))
  const border = px(declaration(shared, 'border'))
  const dial = px(declaration('.totp-countdown', 'height'))

  const totpHeight = dial + padding * 2 + border * 2
  assert.ok(
    totpHeight <= minHeight,
    `the 2FA button resolves to ${totpHeight}px against a shared ${minHeight}px minimum, so it stands taller than "Open site". ` +
      `The dial is ${dial}px; it must be at most ${minHeight - padding * 2 - border * 2}px.`,
  )
})

test('the sidebar draws its own overlays rather than the theme-tinted ones', () => {
  const css = readFileSync(join(root, 'src', 'app.css'), 'utf8')
  const offenders = []
  for (const line of css.split('\n')) {
    if (!/^\s*\.(sidebar|lock-button|nav-icon|nav-label)/.test(line)) continue
    if (/var\(--control-/.test(line)) offenders.push(line.trim().slice(0, 100))
  }
  assert.deepEqual(
    offenders,
    [],
    `these sidebar rules use a theme-tinted overlay on a surface that is dark in both themes:\n  ${offenders.join('\n  ')}`,
  )
  for (const name of ['--sidebar-hover', '--sidebar-active-layer', '--sidebar-active-top', '--sidebar-active-lift']) {
    assert.ok(css.includes(`${name}:`), `${name} is not declared in src/app.css`)
  }
})

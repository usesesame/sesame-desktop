import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

// design/tokens.css is canonical here and has no downstream copies to keep in
// step: the website, the account and admin portals, and the browser extension
// each own their snapshot in their own repository. What remains worth checking
// is that the canonical file is still shaped the way every consumer reads it.
const root = dirname(dirname(fileURLToPath(import.meta.url)))
const canonical = join(root, 'design', 'tokens.css')

const REQUIRED_BLOCKS = [/^:root \{/m, /^:root\[data-theme="dark"\] \{/m]
const REQUIRED_TOKENS = [
  'font-ui',
  'font-display',
  'font-code',
  'radius-sm',
  'radius-md',
  'radius-lg',
  'radius-pill',
  'space-1',
  'space-7',
  'type-1',
  'type-6',
  'accent',
  'gold',
  'danger',
  'surface',
  'border',
  'text',
]

function block(css, pattern) {
  const start = css.search(pattern)
  if (start < 0) throw new Error(`design/tokens.css has no block matching ${pattern}`)
  const open = css.indexOf('{', start)
  let depth = 0
  for (let index = open; index < css.length; index += 1) {
    if (css[index] === '{') depth += 1
    else if (css[index] === '}') {
      depth -= 1
      if (depth === 0) return css.slice(open + 1, index)
    }
  }
  throw new Error(`unterminated block matching ${pattern}`)
}

function declarations(text) {
  const found = new Map()
  for (const match of text.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) found.set(match[1], match[2].trim())
  return found
}

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    if (['node_modules', 'dist', 'test-results', 'target'].includes(name)) return []
    const full = join(dir, name)
    if (statSync(full).isDirectory()) return sourceFiles(full)
    return /\.(css|svelte)$/.test(name) ? [full] : []
  })
}

function fail(message, problems) {
  console.error(`design tokens: ${message}\n  ${problems.join('\n  ')}`)
  process.exit(1)
}

function luminance(hex) {
  const value = hex.replace('#', '')
  const [r, g, b] = [0, 2, 4]
    .map((index) => parseInt(value.slice(index, index + 2), 16) / 255)
    .map((channel) => (channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(first, second) {
  return (Math.max(luminance(first), luminance(second)) + 0.05) / (Math.min(luminance(first), luminance(second)) + 0.05)
}

const mode = process.argv[2]
if (mode !== 'check' && mode !== 'sync') {
  console.error('Usage: node tools/design-tokens.mjs sync|check')
  process.exit(1)
}

let css
try {
  css = readFileSync(canonical, 'utf8')
} catch {
  console.error('design tokens: design/tokens.css is missing.')
  process.exit(1)
}

let light
let dark
try {
  light = declarations(block(css, REQUIRED_BLOCKS[0]))
  dark = declarations(block(css, REQUIRED_BLOCKS[1]))
} catch (error) {
  console.error(`design tokens: ${error.message}`)
  process.exit(1)
}

const missing = REQUIRED_TOKENS.filter((name) => !light.has(name))
if (missing.length) {
  console.error(`design tokens: design/tokens.css is missing ${missing.join(', ')}`)
  process.exit(1)
}

if (mode === 'sync') {
  console.log('design tokens: nothing to sync, every other surface owns its snapshot in its own repository')
  process.exit(0)
}

const rootBlock = block(css, REQUIRED_BLOCKS[0])
for (const [pattern, name] of [
  [/font-family:\s*var\(--font-ui\)/, 'font-family: var(--font-ui)'],
  [/background:\s*var\(--bg\)/, 'background: var(--bg)'],
  [/color:\s*var\(--text\)/, 'color: var(--text)'],
]) {
  if (!pattern.test(rootBlock)) fail(':root no longer sets the base typography', [name])
}

for (const [name, blockText] of [['light', rootBlock], ['dark', block(css, REQUIRED_BLOCKS[1])]]) {
  for (const [token, target] of [
    ['--surface-2', '--surface'],
    ['--surface-3', '--bg-workspace'],
    ['--surface-inset', '--bg-workspace'],
    ['--surface-note', '--bg-workspace'],
  ]) {
    if (!new RegExp(`${token}:\\s*var\\(${target}\\)`).test(blockText)) {
      fail(`${name} surface aliases drifted`, [`${token} must resolve to ${target}`])
    }
  }
}

for (const retired of ['--border-input-focus', '--focus-glow', '--field-border-focus']) {
  if (css.includes(`${retired}:`)) {
    fail('a retired focus token is declared again', [`${retired}: focus is --field-ring alone, hover is --field-border-hover`])
  }
}
for (const required of ['--field-ring', '--field-border-hover']) {
  if (!css.includes(`${required}:`)) fail('a focus token is missing', [required])
}

const fieldRing = light.get('field-ring')
if (!fieldRing || !/var\(--focus-ring\)/.test(fieldRing)) {
  fail('--field-ring no longer draws the shared focus token', [fieldRing ?? '--field-ring is not declared'])
}
if (/0 0 0 1px/.test(fieldRing)) {
  fail('--field-ring draws the doubled 1px edge the halo replaced', [fieldRing])
}

for (const [name, palette] of [['light', light], ['dark', dark]]) {
  const focus = palette.get('focus-ring')
  const surface = palette.get('surface')
  if (!focus || !surface || !/^#[0-9a-fA-F]{6}$/.test(focus) || !/^#[0-9a-fA-F]{6}$/.test(surface)) {
    fail(`${name} focus ring or surface is not a plain colour this check can measure`, [`focus=${focus} surface=${surface}`])
  }
  const ratio = contrast(focus, surface)
  if (ratio < 3) fail(`${name} focus ring contrast is ${ratio.toFixed(2)}:1, below 3:1`, [`--focus-ring ${focus} on --surface ${surface}`])
}

const shared = new Set([...light.keys(), ...dark.keys()])
const files = sourceFiles(join(root, 'src'))
const local = new Set(shared)
for (const file of files) for (const token of declarations(readFileSync(file, 'utf8')).keys()) local.add(token)

const undefinedTokens = []
for (const file of files) {
  for (const match of readFileSync(file, 'utf8').matchAll(/var\(\s*(--[a-z0-9-]+)\s*\)/g)) {
    if (!local.has(match[1].replace(/^--/, ''))) undefinedTokens.push(`${relative(root, file)} uses ${match[1]}`)
  }
}
if (undefinedTokens.length) {
  fail('the desktop app references custom properties nothing defines, so those declarations silently do not apply', undefinedTokens)
}

const whiteOnTheme = []
for (const file of files) {
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!/color:\s*(#fff\b|#ffffff\b|white\b)/i.test(line)) continue
    if (!/background(-color)?:\s*var\(--/.test(line)) continue
    whiteOnTheme.push(`${relative(root, file)}: ${line.trim().slice(0, 90)}`)
  }
}
if (whiteOnTheme.length) fail('hardcoded white over a themed background', whiteOnTheme)

const lowercaseWordmark = []
for (const parts of [
  ['src', 'lib', 'ui', 'Sidebar.svelte'],
  ['src', 'lib', 'ui', 'AppChrome.svelte'],
  ['src', 'lib', 'ui', 'RecoveryKitScreen.svelte'],
]) {
  if (/>\s*sesame\s*</.test(readFileSync(join(root, ...parts), 'utf8'))) {
    lowercaseWordmark.push(`${parts.join('/')} renders the wordmark lowercase; design/tokens.css says Sesame`)
  }
}
if (lowercaseWordmark.length) fail('the wordmark is spelled inconsistently', lowercaseWordmark)

const appCss = readFileSync(join(root, 'src', 'app.css'), 'utf8')
const appLines = appCss.split('\n')

const fieldFocus = []
for (const line of appLines) {
  if (!/:focus/.test(line)) continue
  if (!/\b(input|textarea|select|search-box)\b/.test(line)) continue
  for (const [pattern, name] of [
    [/border-color:\s*var\(--border-input-focus\)/, 'border-color: var(--border-input-focus)'],
    [/border-color:\s*var\(--accent-link\)/, 'border-color: var(--accent-link)'],
    [/box-shadow:\s*var\(--focus-glow\)/, 'box-shadow: var(--focus-glow)'],
    [/outline:\s*\d+px solid/, 'a solid outline'],
  ]) {
    if (pattern.test(line)) fieldFocus.push(`${name} in ${line.trim().slice(0, 90)}`)
  }
}
if (fieldFocus.length) fail('these field focus rules bypass the shared treatment', fieldFocus)

const unsilenced = []
for (const [index, line] of appLines.entries()) {
  if (!/box-shadow:[^;]*var\(--field-ring(-danger)?\)/.test(line)) continue
  const wrapper = line.match(/^(\S+?)(:focus-within|:has\(input:focus)/)
  if (!wrapper) continue
  const base = wrapper[1]
  const silenced = appLines.some(
    (candidate) =>
      candidate !== line &&
      candidate.includes(base) &&
      /:focus(-visible)?\b/.test(candidate) &&
      /box-shadow: none/.test(candidate),
  )
  if (!silenced) unsilenced.push(`app.css:${index + 1} rings ${base} without silencing the input inside it`)
}
if (unsilenced.length) fail('a field would draw two concentric halos', unsilenced)

const selected = []
for (const line of appLines) {
  if (!/\.(active|selected)\b[^{]*\{/.test(line)) continue
  if (!/background|box-shadow/.test(line)) continue
  if (line.includes('--control-active-bg')) continue
  if (/:hover|:focus|:active\b/.test(line)) continue
  if (/^\s*\.(sidebar|lock-button)/.test(line)) continue
  if (/::after|::before/.test(line)) continue
  if (/:not\(\.(active|selected)\)/.test(line)) continue
  if (/switch|toggle-check|favourite|active-filter/.test(line)) continue
  selected.push(line.trim().slice(0, 96))
}
if (selected.length) fail('these active states do not use --control-active-bg', selected)

function declaration(selector, property) {
  const line = appLines.find((candidate) => candidate.startsWith(selector + ' {'))
  if (!line) fail('the shared action button rule moved', [`${selector} is no longer a single-line rule this check can read`])
  const body = line.match(/\{([^}]*)\}/)
  const found = body?.[1].match(new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;]+)`))
  if (!found) fail('the shared action button rule changed shape', [`${selector} no longer sets ${property}`])
  return found[1].trim()
}

function pixels(value) {
  const found = value.match(/(-?[\d.]+)px/)
  if (!found) fail('expected a pixel length', [value])
  return Number(found[1])
}

const minHeight = pixels(declaration('.site-action, .totp-action', 'min-height'))
const padding = pixels(declaration('.site-action, .totp-action', 'padding'))
const border = pixels(declaration('.site-action, .totp-action', 'border'))
const dial = pixels(declaration('.totp-countdown', 'height'))
const totpHeight = dial + padding * 2 + border * 2
if (totpHeight > minHeight) {
  fail(`the 2FA button resolves to ${totpHeight}px against a shared ${minHeight}px minimum`, [
    `the dial is ${dial}px; it must be at most ${minHeight - padding * 2 - border * 2}px`,
  ])
}

const sidebar = []
for (const line of appLines) {
  if (!/^\s*\.(sidebar|lock-button|nav-icon|nav-label)/.test(line)) continue
  if (/var\(--control-/.test(line)) sidebar.push(line.trim().slice(0, 100))
}
if (sidebar.length) fail('these sidebar rules bypass the navigation surface tokens', sidebar)
for (const name of ['--sidebar-hover', '--sidebar-active-layer', '--sidebar-active-top', '--sidebar-active-lift']) {
  if (!appCss.includes(`${name}:`)) fail('a sidebar token is missing', [`${name} is not declared in src/app.css`])
}

console.log(`design tokens: design/tokens.css is well formed, ${light.size} tokens in the light block; ${files.length} desktop sources use only defined tokens`)

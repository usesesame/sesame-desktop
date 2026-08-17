import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const canonical = join(root, 'design', 'tokens.css')
const source = join(root, 'extensions', 'sesame', 'design', 'tokens.css')
const adminSource = join(root, 'admin', 'design', 'tokens.css')
const websiteSource = join(root, 'website', 'design', 'tokens.css')
const accountSource = join(root, 'account', 'design', 'tokens.css')
const target = join(root, 'extensions', 'sesame', 'src', 'content', 'overlay-tokens.ts')

const OVERLAY_TOKENS = [
  'font-ui',
  'font-display',
  'surface',
  'text-heading',
  'text-muted',
  'text-faint',
  'border',
  'border-strong',
  'accent',
  'accent-hover',
  'on-accent',
  'gold',
  'gold-mark-text',
  'radius-sm',
  'radius-md',
  'shadow-pop',
]

function declarations(block) {
  const found = new Map()
  for (const match of block.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    found.set(match[1], match[2].trim())
  }
  return found
}

function block(css, pattern) {
  const start = css.search(pattern)
  if (start < 0) throw new Error(`design/tokens.css has no block matching ${pattern}`)
  const open = css.indexOf('{', start)
  let depth = 0
  for (let i = open; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1
    else if (css[i] === '}') {
      depth -= 1
      if (depth === 0) return css.slice(open + 1, i)
    }
  }
  throw new Error(`unterminated block matching ${pattern}`)
}

function collect() {
  const css = readFileSync(source, 'utf8')
  const light = declarations(block(css, /^:root \{/m))
  const dark = declarations(block(css, /^:root\[data-theme="dark"\] \{/m))

  const missing = OVERLAY_TOKENS.filter((name) => !light.has(name))
  if (missing.length) {
    throw new Error(`design/tokens.css is missing overlay tokens: ${missing.join(', ')}`)
  }

  const pick = (map, fallback) =>
    OVERLAY_TOKENS.map((name) => `  --${name}: ${map.get(name) ?? fallback.get(name)};`).join('\n')

  return { light: pick(light, light), dark: pick(dark, light) }
}

function render({ light, dark }) {
  const indentedDark = dark.split('\n').map((line) => `  ${line}`).join('\n')
  return `// GENERATED FILE. Do not edit.
//
// Written from design/tokens.css. Run \`npm run design:tokens:sync\`;
// \`npm run design:tokens:check\` fails when stale. The overlay's shadow
// host sets \`all:initial\`, so it needs this bounded copy.

export const OVERLAY_TOKEN_CSS = \`:host {
${light}
}

@media (prefers-color-scheme: dark) {
  :host {
${indentedDark}
  }
}\`
`
}

const mode = process.argv[2]

if (mode === 'sync') {
  const canonicalTokens = readFileSync(canonical, 'utf8')
  writeFileSync(source, canonicalTokens)
  writeFileSync(adminSource, canonicalTokens)
  writeFileSync(websiteSource, canonicalTokens)
  writeFileSync(accountSource, canonicalTokens)
  writeFileSync(target, render(collect()))
  console.log('design tokens: refreshed the website, account, admin, and extension snapshots and overlay tokens')
} else if (mode === 'check') {
  if (readFileSync(source, 'utf8') !== readFileSync(canonical, 'utf8')) {
    console.error(
      'design tokens: extensions/sesame/design/tokens.css is not the current monorepo snapshot.\n' +
        'Run `npm run design:tokens:sync` and commit the result.',
    )
    process.exit(1)
  }
  if (readFileSync(adminSource, 'utf8') !== readFileSync(canonical, 'utf8')) {
    console.error(
      'design tokens: admin/design/tokens.css is not the current monorepo snapshot.\n' +
        'Run `npm run design:tokens:sync` and commit the result.',
    )
    process.exit(1)
  }
  if (readFileSync(accountSource, 'utf8') !== readFileSync(canonical, 'utf8')) {
    console.error(
      'design tokens: account/design/tokens.css is not the current monorepo snapshot.\n' +
        'Run `npm run design:tokens:sync` and commit the result.',
    )
    process.exit(1)
  }
  if (readFileSync(websiteSource, 'utf8') !== readFileSync(canonical, 'utf8')) {
    console.error(
      'design tokens: website/design/tokens.css is not the current monorepo snapshot.\n' +
        'Run `npm run design:tokens:sync` and commit the result.',
    )
    process.exit(1)
  }
  const expected = render(collect())
  let actual
  try {
    actual = readFileSync(target, 'utf8')
  } catch {
    console.error('design tokens: overlay-tokens.ts is missing. Run `npm run design:tokens:sync`.')
    process.exit(1)
  }
  if (actual !== expected) {
    console.error(
      'design tokens: overlay-tokens.ts does not match design/tokens.css.\n' +
        'The browser overlay would ship different colours from the rest of Sesame.\n' +
        'Run `npm run design:tokens:sync` and commit the result.',
    )
    process.exit(1)
  }
  console.log('design tokens: website, account, admin, and extension snapshots match design/tokens.css')
} else {
  console.error('Usage: node tools/design-tokens.mjs sync|check')
  process.exit(1)
}

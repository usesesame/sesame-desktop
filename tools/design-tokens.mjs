import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
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
  'radius-sm',
  'radius-md',
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
try {
  light = declarations(block(css, REQUIRED_BLOCKS[0]))
  block(css, REQUIRED_BLOCKS[1])
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
} else {
  console.log(`design tokens: design/tokens.css is well formed, ${light.size} tokens in the light block`)
}

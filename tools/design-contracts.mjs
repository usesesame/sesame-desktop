export const TYPE_ALLOWLIST = [
  { property: 'font-size', selector: '.brand', reason: 'wordmark lockup keeps its fixed size' },
  { property: 'font-size', selector: '.sesame-mark', reason: 'mark glyph size' },
  { property: 'font-size', selector: '.empty-icon', reason: 'empty-state glyph size' },
]

const LITERAL_SIZE = /^(?!var\(|inherit|initial|unset|revert)[0-9]*\.?[0-9]+(px|rem|em|%|pt|ch|ex|vw|vh)\b/
const LITERAL_WEIGHT = /^[0-9]{3}$/
const SHORTHAND_LITERAL = /(^|\s)([0-9]*\.?[0-9]+(px|rem|em|%|pt|ch|ex|vw|vh))(\s*\/|[;\s]|$)|(^|\s)[0-9]{3}(\s|$)|[0-9]+\s*\/\s*[0-9]+/

export function block(css, pattern) {
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

export function declarations(text) {
  const found = new Map()
  for (const match of text.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) found.set(match[1], match[2].trim())
  return found
}

function rules(css) {
  const found = []
  const stack = []
  let prelude = ''
  for (const char of css) {
    if (char === '{') {
      stack.push(prelude.trim())
      prelude = ''
    } else if (char === '}') {
      if (stack.length && prelude.includes(':')) found.push({ selector: stack[stack.length - 1], declaration: prelude.trim() })
      stack.pop()
      prelude = ''
    } else if (char === ';') {
      if (stack.length && prelude.includes(':')) found.push({ selector: stack[stack.length - 1], declaration: prelude.trim() })
      prelude = ''
    } else {
      prelude += char
    }
  }
  return found
}

function allowlisted(property, selector) {
  return TYPE_ALLOWLIST.some((entry) => entry.property === property && selector.includes(entry.selector))
}

export function findLiteralTypeDeclarations(sources) {
  const violations = []
  for (const { path, text } of sources) {
    for (const { selector, declaration } of rules(text)) {
      const match = declaration.match(/^(font-size|font-weight|font)\s*:\s*(.+)$/s)
      if (!match) continue
      const [, property, rawValue] = match
      const value = rawValue.trim()
      let literal = false
      if (property === 'font-size') literal = LITERAL_SIZE.test(value)
      else if (property === 'font-weight') literal = LITERAL_WEIGHT.test(value)
      else literal = SHORTHAND_LITERAL.test(value)
      if (!literal || allowlisted(property, selector)) continue
      violations.push({ path, selector, property, value })
    }
  }
  return violations
}

export const RADIUS_ALLOWLIST = []

const LITERAL_RADIUS = /[0-9]*\.?[0-9]+(px|rem|em)\b/

export function findLiteralRadiusDeclarations(sources, allowlist = RADIUS_ALLOWLIST) {
  const violations = []
  for (const { path, text } of sources) {
    for (const { selector, declaration } of rules(text)) {
      const match = declaration.match(/^border-radius\s*:\s*(.+)$/s)
      if (!match) continue
      const value = match[1].trim()
      if (value.includes('var(') || !LITERAL_RADIUS.test(value)) continue
      if (allowlist.some((entry) => selector.includes(entry.selector))) continue
      violations.push({ path, selector, value })
    }
  }
  return violations
}

export const CONTRAST_PAIRS = [
  { name: 'text on background', foreground: '--text', background: '--bg', floor: 4.5 },
  { name: 'text on surface', foreground: '--text', background: '--surface', floor: 4.5 },
  { name: 'muted text on background', foreground: '--text-muted', background: '--bg', floor: 5 },
  { name: 'muted text on surface', foreground: '--text-muted', background: '--surface', floor: 5 },
  { name: 'eyebrow on background', foreground: '--eyebrow', background: '--bg', floor: 5 },
  { name: 'status text on ok background', foreground: '--ok-text', background: '--ok-bg', floor: 4.5 },
  { name: 'status text on warn background', foreground: '--warn-text', background: '--warn-bg', floor: 4.5 },
  { name: 'status text on danger background', foreground: '--danger', background: '--danger-bg', floor: 4.5 },
  { name: 'status text on gold background', foreground: '--gold-text', background: '--gold-soft-bg', floor: 4.5 },
  { name: 'on-accent on accent', foreground: '--on-accent', background: '--accent', floor: 4.5 },
  { name: 'on-danger on danger', foreground: '--on-danger', background: '--danger', floor: 4.5 },
  { name: 'field border on field background', foreground: '--border-input', background: '--field-bg', floor: 3 },
  { name: 'focus ring on surface', foreground: '--focus-ring', background: '--surface', floor: 3 },
]

export function resolveColour(declarationsMap, name, depth = 0) {
  if (depth > 8) return null
  const value = declarationsMap.get(name.replace(/^--/, ''))
  if (value == null) return null
  const alias = value.match(/^var\(\s*(--[a-z0-9-]+)\s*\)$/)
  if (alias) return resolveColour(declarationsMap, alias[1], depth + 1)
  return /^#[0-9a-fA-F]{6}$/.test(value) ? value : null
}

export function contrastRatio(first, second) {
  const luminance = (hex) => {
    const value = hex.replace('#', '')
    const [r, g, b] = [0, 2, 4]
      .map((index) => parseInt(value.slice(index, index + 2), 16) / 255)
      .map((channel) => (channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b
  }
  return (Math.max(luminance(first), luminance(second)) + 0.05) / (Math.min(luminance(first), luminance(second)) + 0.05)
}

export function evaluateContrast(theme, declarationsMap, pairs = CONTRAST_PAIRS) {
  const violations = []
  for (const pair of pairs) {
    const foreground = resolveColour(declarationsMap, pair.foreground)
    const background = resolveColour(declarationsMap, pair.background)
    if (!foreground || !background) {
      violations.push({ theme, name: pair.name, floor: pair.floor, ratio: null, foreground, background })
      continue
    }
    const ratio = contrastRatio(foreground, background)
    if (ratio < pair.floor) violations.push({ theme, name: pair.name, floor: pair.floor, ratio, foreground, background })
  }
  return violations
}

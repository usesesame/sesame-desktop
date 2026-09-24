export const TYPE_ALLOWLIST = [
  { property: 'font-size', selector: '.brand', reason: 'wordmark lockup keeps its fixed size' },
  { property: 'font-size', selector: '.sesame-mark', reason: 'mark glyph size' },
  { property: 'font-size', selector: '.empty-icon', reason: 'empty-state glyph size' },
]

const LITERAL_SIZE = /^(?!var\(|inherit|initial|unset|revert)[0-9]*\.?[0-9]+(px|rem|em|%|pt|ch|ex|vw|vh)\b/
const LITERAL_WEIGHT = /^[0-9]{3}$/
const SHORTHAND_LITERAL = /(^|\s)([0-9]*\.?[0-9]+(px|rem|em|%|pt|ch|ex|vw|vh))(\s*\/|[;\s]|$)|(^|\s)[0-9]{3}(\s|$)|[0-9]+\s*\/\s*[0-9]+/

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

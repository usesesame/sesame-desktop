#!/usr/bin/env node
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const output = join(root, 'src-tauri', 'src', 'terminal_text_tables.rs')

const HIDDEN_FORMATTING = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}\p{Default_Ignorable_Code_Point}]/u
const MARK = /\p{M}/u
const BLANK_LOOKING_POINTS = new Set([0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180e, 0x180f, 0x2800, 0x3164, 0xffa0, 0x1d159, 0x1d173, 0x1d174, 0x1d175, 0x1d176, 0x1d177, 0x1d178, 0x1d179, 0x1d17a])

function ranges(test) {
  const found = []
  let start = null
  for (let point = 0; point <= 0x110000; point += 1) {
    const inside = point <= 0x10ffff && test(point)
    if (inside && start === null) start = point
    if (!inside && start !== null) {
      found.push([start, point - 1])
      start = null
    }
  }
  return found
}

function hex(point) {
  return `0x${point.toString(16).padStart(4, '0')}`
}

function table(name, found) {
  const rows = found.map(([start, end]) => `    (${hex(start)}, ${hex(end)}),`).join('\n')
  return `pub(crate) const ${name}: &[(u32, u32)] = &[\n${rows}\n];\n`
}

const hidden = ranges((point) => BLANK_LOOKING_POINTS.has(point) || HIDDEN_FORMATTING.test(String.fromCodePoint(point)))
const marks = ranges((point) => MARK.test(String.fromCodePoint(point)))

writeFileSync(output, [
  `#[cfg(test)]\npub(crate) const UNICODE_VERSION: &str = "${process.versions.unicode}";\n`,
  table('HIDDEN', hidden),
  table('MARKS', marks),
].join('\n'))
console.log(`Wrote ${hidden.length} hidden and ${marks.length} mark ranges for Unicode ${process.versions.unicode}.`)

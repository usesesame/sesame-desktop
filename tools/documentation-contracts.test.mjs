import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, normalize, posix, relative, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { requireFiles } from './repository-files.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const RETAINED_DATED_DOCUMENTS = new Map()

test('every relative documentation link resolves', () => {
  const broken = []
  for (const file of requireFiles('*.md', 10)) {
    const from = dirname(join(root, file))
    const text = readFileSync(join(root, file), 'utf8')
    for (const match of text.matchAll(/\]\(([^)\s#]+\.md)(?:#[^)\s]*)?\)/g)) {
      const target = match[1]
      if (/^[a-z]+:/i.test(target)) continue
      if (!existsSync(resolve(from, target))) broken.push(`${file} -> ${target}`)
    }
  }
  assert.deepEqual(broken, [], `these documentation links point at files that do not exist:\n  ${broken.join('\n  ')}`)
})

test('a dated or work-item document needs a recorded reason to stay', () => {
  const dated = requireFiles('*.md', 10).filter((file) => /\d{4}-\d{2}-\d{2}|^docs\/[A-Z]{2,4}-\d{3}/.test(posix.basename(file)) || /\d{4}-\d{2}-\d{2}/.test(file))
  const undeclared = dated.filter((file) => !RETAINED_DATED_DOCUMENTS.has(file))
  assert.deepEqual(
    undeclared,
    [],
    `add a reason and an exit condition here, or fold the findings into a current document:\n  ${undeclared.join('\n  ')}`,
  )
  for (const [file, reason] of RETAINED_DATED_DOCUMENTS) {
    assert.ok(existsSync(join(root, file)), `${file} is retired; remove its entry from this contract`)
    assert.ok(reason.length > 40, `${file} needs a real reason, not a label`)
  }
})

test('no document promises evidence the repository does not keep', () => {
  // release-artifacts/ and release-evidence/ are ignored working directories; a clone never has them, so no document may claim evidence is retained there.
  const offenders = []
  for (const file of requireFiles('*.md', 10)) {
    const text = readFileSync(join(root, file), 'utf8')
    for (const match of text.matchAll(/[^.\n]*\b(?:retained|is retained|lives|stored)\b[^.\n]*`?release-(?:artifacts|evidence)\/[^.\n]*/g)) {
      const sentence = match[0].trim()
      if (/removed|no longer|was held|not retained/.test(sentence)) continue
      offenders.push(`${file}: ${sentence.slice(0, 120)}`)
    }
  }
  assert.deepEqual(offenders, [], `these claims survive only on one machine:\n  ${offenders.join('\n  ')}`)
})

test('no source comment carries a work-item identifier', () => {
  const families = /\b(?:SRA-\d{1,2}|SYNC-\d{1,2}|SYN-PT-\d{1,2}|APP-\d{2}|OPS-\d{2}|CORE-\d{3}|QLT-\d{3}|INS-\d{3}|PEN-\d{3}|BRS-\d{3}|IOS-\d{3}|AND-\d{3})\b/
  const comment = /^\s*(?:\/\/[/!]?|--|#)/
  const offenders = []

  for (const file of requireFiles('*', 100)) {
    if (!/\.(go|rs|ts|tsx|mjs|js|svelte|sql)$/.test(file)) continue
    const lines = readFileSync(join(root, file), 'utf8').split('\n')
    for (const [index, line] of lines.entries()) {
      if (comment.test(line) && families.test(line)) {
        offenders.push(`${file}:${index + 1}: ${line.trim().slice(0, 80)}`)
      }
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `keep the reason, drop the identifier:\n  ${offenders.join('\n  ')}`,
  )
})

test('retired documents leave no orphan references', () => {
  const retired = [
    'INDEPENDENT-PROJECT-REVIEW-2026-08-08.md',
    'LOCAL-VAULT-CRYPTO-REVIEW-2026-08-11.md',
    'MONOREPO-BASELINE-HASHES-2026-08-14.md',
    'RELEASE-CANDIDATE-2026-08-09.md',
    'SECURITY-AUDIT-2026-07-30.md',
    'SECURITY-AUDIT-2026-08-01.md',
    'SYN-001A-PENTEST-2026-08-11.md',
    'SYNC-SECURITY-REVIEW.md',
    'SECURITY-REVIEW.md',
    'RELEASE-INTEGRITY.md',
    'VOICE.md',
    'FRONTEND.md',
    'REPOSITORY-BOUNDARY-GATE.md',
    'BROWSER-EXTENSION-EXTRACTION.md',
    'SERVER-EXTRACTION.md',
    'WEBSITE-EXTRACTION.md',
    'DESKTOP-RENAME.md',
    'GOVERNANCE.md',
  ]
  const offenders = []
  for (const file of requireFiles('*', 100)) {
    if (normalize(file) === normalize(relative(root, fileURLToPath(import.meta.url)))) continue
    let text
    try {
      text = readFileSync(join(root, file), 'utf8')
    } catch {
      continue
    }
    for (const name of retired) {
      if (text.includes(name)) offenders.push(`${file} -> ${name}`)
    }
  }
  assert.deepEqual(offenders, [], `these files still point at a retired document:\n  ${offenders.join('\n  ')}`)
})

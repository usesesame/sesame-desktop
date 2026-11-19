import { describe, expect, test } from 'vitest'
import vectors from '../../src-tauri/contracts/cli/v1/vectors.json'
import source from '../../src-tauri/src/terminal_text_tables.rs?raw'
import { MAX_MARKS_PER_CHARACTER, UNREADABLE_NAME, hidesCharacter, isMark, allowedRequestWords, approvalHeading, approvalSummary, cancelledLine, remainingWords, shownText, unlockLine } from './terminal-text'

const plainProse = /[—–()]/

describe('text a terminal sent', () => {
  test('control, format and direction characters become a visible mark', () => {
    expect(shownText('Northwind‮mail')).toBe('Northwind?mail')
    expect(shownText('a\u0000b\u0007c\u001bd')).toBe('a?b?c?d')
    expect(shownText('North​wind⁦⁩')).toBe('North?wind??')
    expect(shownText('one two three')).toBe('one?two?three')
    expect(shownText('private')).toBe('?private')
  })

  test('unusual spaces become plain spaces and the text is normalised', () => {
    expect(shownText('North wind　mail')).toBe('North wind mail')
    expect(shownText('Café')).toBe('Café')
  })

  test('long text is cut to a fixed number of characters', () => {
    const shown = shownText('W'.repeat(400))
    expect([...shown]).toHaveLength(80)
    expect(shown.endsWith('…')).toBe(true)
    expect([...shownText('\u{1F600}'.repeat(100), 10)]).toHaveLength(10)
    expect(shownText('pts/3', 24)).toBe('pts/3')
    const marked = shownText('x\u0301\u0301'.repeat(80))
    expect([...marked].length).toBeLessThanOrEqual(80)
    expect(marked.endsWith('x\u0301\u0301…')).toBe(true)
    expect(shownText('x\u0301\u0301'.repeat(26))).toBe('x\u0301\u0301'.repeat(26))
    expect(shownText(undefined)).toBe(UNREADABLE_NAME)
    expect(shownText('\u3164\u3164', 10)).toBe('Unreadabl…')
    expect(shownText('\u3164', 15)).toBe(UNREADABLE_NAME)
    expect(shownText('Readable', 0)).toBe('')
    expect(shownText('Readable', 1)).toBe('…')
  })
})

describe('the rule the terminal tool shares', () => {
  const character = (hex: string) => String.fromCodePoint(Number.parseInt(hex, 16))

  test.each([
    ['standIns', '?'],
    ['spaces', ' '],
    ['kept', null],
  ] as const)('the %s cases read the same in the window as in the terminal', (group, shown) => {
    const points: string[] = vectors.shownTextCases[group]
    expect(points.length).toBeGreaterThan(0)
    for (const point of points) {
      const value = character(point)
      expect(shownText(`a${value}b`), point).toBe(`a${shown ?? value}b`)
    }
  })
})

describe('the tables the terminal tool carries', () => {
  const runtime = (globalThis as { process?: { versions?: { unicode?: string } } }).process?.versions?.unicode

  function table(name: string): Array<[number, number]> {
    const body = source.match(new RegExp(`const ${name}: &\\[\\(u32, u32\\)\\] = &\\[([^\\]]*)\\];`))
    expect(body, name).not.toBeNull()
    return [...(body?.[1] ?? '').matchAll(/\((0x[0-9a-f]+), (0x[0-9a-f]+)\)/g)].map((pair) => [Number(pair[1]), Number(pair[2])])
  }

  function inside(ranges: Array<[number, number]>, point: number): boolean {
    let low = 0
    let high = ranges.length - 1
    while (low <= high) {
      const middle = (low + high) >> 1
      const [start, end] = ranges[middle]
      if (point < start) high = middle - 1
      else if (point > end) low = middle + 1
      else return true
    }
    return false
  }

  test('were made from the Unicode version this runtime uses, so the check below is exact', () => {
    expect(runtime).toBeDefined()
    expect(source).toContain(`UNICODE_VERSION: &str = "${runtime}";`)
  })

  test('agree with the window on every code point about hidden characters and combining marks', () => {
    const hidden = table('HIDDEN')
    const marks = table('MARKS')
    const disagreements: string[] = []
    for (let point = 0; point <= 0x10ffff; point += 1) {
      const character = String.fromCodePoint(point)
      if (inside(hidden, point) !== hidesCharacter(character)) disagreements.push(`hidden ${point.toString(16)}`)
      if (inside(marks, point) !== isMark(character)) disagreements.push(`mark ${point.toString(16)}`)
      if (disagreements.length > 20) break
    }
    expect(disagreements).toEqual([])
  })

  test('the shared mark cases read the same in the window as in the terminal', () => {
    const cases: Array<[string, string]> = vectors.shownTextCases.marks as Array<[string, string]>
    expect(cases.length).toBeGreaterThan(0)
    for (const [input, shown] of cases) expect(shownText(input), input).toBe(shown)
  })
})

describe('characters that draw outside their place or look blank', () => {
  test('combining marks are capped per character and the rest become one stand-in', () => {
    const stacked = 'x' + '\u0301'.repeat(45) + 'b'
    const shown = shownText(stacked)
    expect([...shown]).toHaveLength(1 + MAX_MARKS_PER_CHARACTER + 2)
    expect(shown).toBe('x\u0301\u0301?b')
    expect(shownText('Caf\u0065\u0301 mail')).toBe('Caf\u00E9 mail')
    expect(shownText('\u0301\u0302\u0303Northwind')).toBe('?Northwind')
    expect(shownText('North wind \u0301\u0301')).toBe('North wind ?')
    expect(shownText('\u0E01\u0E34\u0E48')).toBe('\u0E01\u0E34\u0E48')
  })

  test.each([
    ['Hangul filler', '\u3164'],
    ['Hangul choseong filler', '\u115F'],
    ['Hangul jungseong filler', '\u1160'],
    ['halfwidth Hangul filler', '\uFFA0'],
    ['braille blank', '\u2800'],
    ['combining grapheme joiner', '\u034F'],
    ['Khmer inherent vowel', '\u17B4'],
    ['Mongolian free variation selector', '\u180B'],
    ['emoji variation selector', '\uFE0F'],
    ['text variation selector', '\uFE0E'],
    ['ideographic variation selector', '\u{E0100}'],
  ])('a %s becomes the visible stand-in', (_name, character) => {
    expect(shownText(`North${character}wind`)).toBe('North?wind')
  })

  test('a name that is empty or only stand-ins after cleaning reads as unreadable', () => {
    for (const value of ['', '   ', '\u3164\u3164', '\u2800 \u115F\u1160', '\u202E\u200B', '\u0301\u0301', '\u0000\u0007']) {
      expect(shownText(value)).toBe(UNREADABLE_NAME)
    }
    expect(shownText('?')).toBe(UNREADABLE_NAME)
    expect(shownText('a\u3164')).toBe('a?')
  })
})

describe('what the dialog says', () => {
  test('every command is named in plain words and never repeats the field a terminal sent', () => {
    expect(approvalHeading({ command: 'list', copy: false, fieldHidden: false })).toBe('A terminal wants the names of all your items')
    expect(approvalHeading({ command: 'get', copy: false, fieldHidden: false })).toBe('A terminal wants to read an item')
    expect(approvalHeading({ command: 'get', field: 'password', copy: false, fieldHidden: true })).toBe('A terminal wants the password of an item')
    expect(approvalHeading({ command: 'get', field: 'password', copy: true, fieldHidden: true })).toBe('A terminal wants to copy the password of an item')
    expect(approvalHeading({ command: 'get', field: 'Allow this terminal', copy: false, fieldHidden: false })).toBe('A terminal wants one field of an item')
    expect(approvalHeading({ command: 'get', field: 'constructor', copy: false, fieldHidden: true })).toBe('A terminal wants a hidden field of an item')
    expect(approvalHeading({ command: 'totp', copy: false, fieldHidden: false })).toBe('A terminal wants a one-time code')
    expect(approvalHeading({ command: 'totp', copy: true, fieldHidden: false })).toBe('A terminal wants to copy a one-time code')
  })

  test('the summary says whether the value is printed or copied', () => {
    expect(approvalSummary({ command: 'get', field: 'password', copy: true, fieldHidden: true })).toMatch(/copies the value to the clipboard instead of printing it/)
    expect(approvalSummary({ command: 'get', field: 'password', copy: false, fieldHidden: true })).toMatch(/prints this hidden value/)
    expect(approvalSummary({ command: 'list', copy: false, fieldHidden: false })).toMatch(/no passwords/)
  })

  test('every closing reason has its own sentence', () => {
    const lines = ['expired', 'connectionClosed', 'vaultChanged', 'preempted', 'somethingNew'].map(cancelledLine)
    expect(new Set(lines).size).toBe(5)
    const waiting = [
      unlockLine({ command: 'get', copy: false }),
      unlockLine({ command: 'list', copy: false }),
      unlockLine({ command: 'totp', copy: true }),
      unlockLine({ command: 'get', field: 'password', copy: false }),
    ]
    for (const line of [...lines, ...waiting]) expect(line).not.toMatch(plainProse)
  })

  test('the lock screen says what a waiting terminal wants without naming the item', () => {
    expect(unlockLine({ command: 'get', field: 'password', copy: false })).toBe('A terminal wants the password of an item. Sesame asks you about it after you unlock.')
    expect(unlockLine({ command: 'get', field: 'password', copy: true })).toBe('A terminal wants to copy the password of an item. Sesame asks you about it after you unlock.')
    expect(unlockLine({ command: 'get', field: 'Recovery PIN', copy: false })).toBe('A terminal wants one field of an item. Sesame asks you about it after you unlock.')
    expect(unlockLine({ command: 'get', copy: false })).toBe('A terminal wants to read an item. Sesame asks you about it after you unlock.')
    expect(unlockLine({ command: 'list', copy: false })).toBe('A terminal wants the names of all your items. Sesame asks you about it after you unlock.')
    expect(unlockLine({ command: 'totp', copy: false })).toBe('A terminal wants a one-time code. Sesame asks you about it after you unlock.')
  })

  test('allowed requests and remaining time read as sentences', () => {
    expect(allowedRequestWords('get', 'password', 'Northwind mail', 'login')).toBe('Read the password of Northwind mail')
    expect(allowedRequestWords('get', 'Recovery PIN', 'Northwind mail', 'login')).toBe('Read a field of Northwind mail')
    expect(allowedRequestWords('totp', 'totp', null, 'login')).toBe('Read the one-time code of a removed login')
    expect(allowedRequestWords('list', undefined, null, undefined)).toBe('Listed every item title')
    expect(remainingWords(212_000)).toBe('3 more minutes')
    expect(remainingWords(270_000)).toBe('4 more minutes')
    expect(remainingWords(300_000)).toBe('5 more minutes')
    expect(remainingWords(60_000)).toBe('1 more minute')
    expect(remainingWords(59_400)).toBe('59 more seconds')
    expect(remainingWords(41_000)).toBe('41 more seconds')
    expect(remainingWords(1_000)).toBe('1 more second')
  })
})

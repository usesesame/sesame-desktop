import { describe, expect, test } from 'vitest'
import { allowedRequestWords, approvalHeading, approvalSummary, cancelledLine, remainingWords, shownText, unlockLine } from './terminal-text'

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
    expect(shownText(undefined)).toBe('')
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
    for (const line of [...lines, unlockLine('get'), unlockLine('list'), unlockLine('totp')]) expect(line).not.toMatch(plainProse)
  })

  test('allowed requests and remaining time read as sentences', () => {
    expect(allowedRequestWords('get', 'password', 'Northwind mail', 'login')).toBe('Read the password of Northwind mail')
    expect(allowedRequestWords('get', 'Recovery PIN', 'Northwind mail', 'login')).toBe('Read a field of Northwind mail')
    expect(allowedRequestWords('totp', 'totp', null, 'login')).toBe('Read the one-time code of a removed login')
    expect(allowedRequestWords('list', undefined, null, undefined)).toBe('Listed every item title')
    expect(remainingWords(212_000)).toBe('4 more minutes')
    expect(remainingWords(41_000)).toBe('41 more seconds')
    expect(remainingWords(1_000)).toBe('1 more second')
  })
})

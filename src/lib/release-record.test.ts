import { describe, expect, test } from 'vitest'
import { RECORD_SCOPE_TEXT, cautionLine, dayLabel, entryDetails, entrySentence, groupByDay, hintLine, isRefusal, statusNotice } from './release-record'
import type { EntryKind, Outcome, ReleaseEntryView, ReleaseRecordHint, ReleaseRecordStatus } from './types'

const titles: Record<string, string> = { 'login-a': 'Northwind' }
const titleFor = (_kind: string, id: string) => titles[id] ?? null

function entry(partial: Partial<ReleaseEntryView>): ReleaseEntryView {
  return { seq: 1, at: 1_800_000_000, kind: 'browserFill', outcome: 'released', fields: [], count: 1, late: false, ...partial }
}

const ALL_KINDS: EntryKind[] = ['browserFill', 'browserSave', 'browserTotp', 'browserCard', 'browserIdentity', 'browserChange', 'browserCreate', 'reveal', 'copy', 'autoType', 'quickAccess', 'csvExport', 'jsonExport', 'backupExport', 'backupCreated', 'recoveryKitSaved', 'attachmentSaved', 'devicePaired', 'emailAlias', 'cleared', 'retentionShortened', 'unreadable', 'interrupted', 'fileChanged', 'lockedOverflow', 'refusalLimit', 'writesLost', 'newer']
const ALL_OUTCOMES: Outcome[] = ['released', 'saved', 'updated', 'denied', 'timedOut', 'connectionClosed', 'vaultChanged', 'withdrawn', 'lookalike', 'noMatch', 'locked', 'busy', 'mismatch', 'replayed', 'neverSave', 'noted']

function readable(text: string) {
  expect(text).not.toMatch(/[—–()]/)
  expect(text).not.toMatch(/proof/i)
  expect(text.trim()).toBe(text)
  expect(text.length).toBeGreaterThan(10)
}

describe('activity sentences', () => {
  test('a released fill names the item and the site', () => {
    expect(entrySentence(entry({ itemId: 'login-a', itemKind: 'login', host: 'example.com' }), titleFor)).toBe('Filled Northwind on example.com')
  })

  test('an item that no longer exists is named by its kind', () => {
    expect(entrySentence(entry({ kind: 'copy', itemId: 'gone', itemKind: 'card', fields: ['cardNumber'] }), titleFor)).toBe('Copied the card number of a removed card')
  })

  test('refusals say what was refused and why', () => {
    expect(entrySentence(entry({ outcome: 'denied', host: 'example.com' }), titleFor)).toBe('You denied a login fill request from example.com')
    expect(entrySentence(entry({ outcome: 'lookalike', host: 'examp1e.com', similarTo: 'example.com' }), titleFor)).toBe('Sesame refused a login fill on examp1e.com because it looks like example.com')
    expect(entrySentence(entry({ kind: 'browserIdentity', outcome: 'timedOut', host: 'example.com' }), titleFor)).toBe('An identity fill request from example.com was not answered in time')
  })

  test('the article fits the request noun', () => {
    expect(entrySentence(entry({ kind: 'browserTotp', outcome: 'timedOut', host: 'example.com' }), titleFor)).toBe('A one-time code fill request from example.com was not answered in time')
    expect(entrySentence(entry({ kind: 'browserIdentity', outcome: 'denied', host: 'example.com' }), titleFor)).toBe('You denied an identity fill request from example.com')
  })

  test('every kind and outcome reads as a sentence without dashes or parentheses', () => {
    for (const kind of ALL_KINDS) {
      for (const outcome of ALL_OUTCOMES) {
        readable(entrySentence(entry({ kind, outcome, host: 'example.com', itemId: 'login-a', itemKind: 'login', fields: ['password'], count: 3 }), titleFor))
      }
    }
    for (const paragraph of RECORD_SCOPE_TEXT) readable(paragraph)
  })

  test('the explanation says what the record leaves out', () => {
    const text = RECORD_SCOPE_TEXT.join(' ')
    expect(text).toContain('one-time codes you only look at')
    expect(text).toContain('breach checks')
    expect(text).toContain('stays on this device')
  })

  test('details show the time, the match, repeats and late writes', () => {
    const details = entryDetails(entry({ matchKind: 'site', count: 4, late: true }))
    expect(details).toContain('Matched by site')
    expect(details).toContain('4 times')
    expect(details).toContain('Written later')
    expect(entryDetails(entry({ kind: 'cleared', outcome: 'noted', count: 12 }))).toContain('12 entries removed')
    expect(entrySentence(entry({ kind: 'retentionShortened', outcome: 'noted', count: 4 }), () => null)).toBe('You shortened how long Sesame keeps activity')
    expect(entryDetails(entry({ kind: 'retentionShortened', outcome: 'noted', count: 4 }))).toContain('4 entries removed')
    expect(entryDetails(entry({ kind: 'csvExport', count: 40 }))).not.toContain('40 times')
  })

  test('an alias request says whether the token was sent', () => {
    expect(entrySentence(entry({ kind: 'emailAlias', outcome: 'released', host: 'app.addy.io' }), titleFor)).toBe('Sent your alias API token to app.addy.io to make a new alias')
    expect(entrySentence(entry({ kind: 'emailAlias', outcome: 'withdrawn', host: 'app.simplelogin.io' }), titleFor)).toBe('Sesame tried to make a new alias but did not send your API token to app.simplelogin.io')
    expect(entrySentence(entry({ kind: 'emailAlias', outcome: 'released' }), titleFor)).toBe('Sent your alias API token to the alias service to make a new alias')
    expect(entrySentence(entry({ kind: 'emailAlias', outcome: 'connectionClosed', host: 'app.addy.io' }), titleFor)).toBe('Sesame may have sent your alias API token to app.addy.io, but the connection ended before an answer')
  })

  test('an entry from a newer version is one plain line with its time', () => {
    const newer = entry({ kind: 'newer', outcome: 'noted' })
    expect(entrySentence(newer, titleFor)).toBe('Something a newer version of Sesame recorded')
    expect(entryDetails(newer)).toBe(entryDetails(entry({ kind: 'backupCreated' })))
    expect(isRefusal(newer.outcome)).toBe(false)
  })

  test('refusals are told apart from releases', () => {
    expect(isRefusal('released')).toBe(false)
    expect(isRefusal('noted')).toBe(false)
    expect(isRefusal('timedOut')).toBe(true)
    expect(isRefusal('lookalike')).toBe(true)
  })
})

describe('activity days', () => {
  test('entries are grouped by local day with plain labels', () => {
    const now = new Date(2026, 10, 16, 15, 0).getTime() / 1_000
    const today = new Date(2026, 10, 16, 9, 0).getTime() / 1_000
    const yesterday = new Date(2026, 10, 15, 22, 0).getTime() / 1_000
    const earlier = new Date(2026, 10, 3, 12, 0).getTime() / 1_000
    const days = groupByDay([entry({ at: today, seq: 3 }), entry({ at: today - 60, seq: 2 }), entry({ at: yesterday }), entry({ at: earlier })], now)
    expect(days.map((day) => day.entries.length)).toEqual([2, 1, 1])
    expect(days[0].label).toBe('Today')
    expect(days[1].label).toBe('Yesterday')
    expect(dayLabel(earlier, now)).not.toMatch(/^[A-Z ]+$/)
  })
})

describe('activity notices', () => {
  const status = (partial: Partial<ReleaseRecordStatus>): ReleaseRecordStatus => ({ available: true, entryCount: 0, retentionDays: 180, unwritten: 0, ...partial })

  test('a write failure is reported before anything else', () => {
    const notice = statusNotice(status({ unwritten: 2, notice: 'unreadable' }))
    expect(notice).toContain('could not write 2 entries')
    readable(notice ?? '')
  })

  test('an unreadable record explains the likely cause', () => {
    const notice = statusNotice(status({ notice: 'unreadable' }))
    expect(notice).toContain('master password change')
    readable(notice ?? '')
  })

  test('a healthy record shows no notice', () => {
    expect(statusNotice(status({}))).toBeNull()
    expect(statusNotice(null)).toBeNull()
  })
})

describe('approval lines', () => {
  const now = new Date(2026, 10, 16, 12, 0).getTime() / 1_000
  const hint = (partial: Partial<ReleaseRecordHint>): ReleaseRecordHint => ({
    approvalId: 'approval-1', host: 'example.com', items: [], recordSince: new Date(2026, 7, 3).getTime() / 1_000, incomplete: false, deniedRecently: 0, ...partial,
  })

  test('a login filled before shows how often and when', () => {
    const line = hintLine(hint({ items: [{ itemId: 'login-a', releasedHere: 12, lastReleasedAt: new Date(2026, 10, 3, 9).getTime() / 1_000 }] }), 'login-a', 'login', now)
    expect(line).toMatch(/^Filled here 12 times, last on (3 November|November 3)\.$/)
  })

  test('a first fill names the start of the record instead of claiming a first time', () => {
    const line = hintLine(hint({ items: [{ itemId: 'login-a', releasedHere: 0 }] }), 'login-a', 'login', now)
    expect(line).toMatch(/^Sesame has no record of filling this login on example\.com since (3 August|August 3)\.$/)
    expect(line).not.toMatch(/first time/i)
  })

  test('an incomplete record says it cannot tell', () => {
    expect(hintLine(hint({ incomplete: true, items: [{ itemId: 'login-a', releasedHere: 4 }] }), 'login-a', 'login', now)).toContain('incomplete')
  })

  test('no selection shows no history line', () => {
    expect(hintLine(hint({ items: [{ itemId: 'login-a', releasedHere: 4 }] }), '', 'login', now)).toBeNull()
  })

  test('a recent denial adds a caution line', () => {
    expect(cautionLine(hint({}), now)).toBeNull()
    expect(cautionLine(hint({ deniedRecently: 1, lastDeniedAt: new Date(2026, 10, 14).getTime() / 1_000 }), now)).toMatch(/^You denied a request from this site on (14 November|November 14)\.$/)
    const several = cautionLine(hint({ deniedRecently: 3, lastDeniedAt: new Date(2026, 10, 14).getTime() / 1_000 }), now)
    expect(several).toContain('3 requests from this site in the last two weeks')
    readable(several ?? '')
  })
})

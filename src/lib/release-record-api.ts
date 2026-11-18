import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { BrowserFillRequest, ReleaseEntryView, ReleaseRecordHint, ReleaseRecordPage, ReleaseRecordQuery, ReleaseRecordStatus } from './types'

const previewMode = typeof window === 'undefined' || !(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await tauriInvoke<T>(cmd, args)
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error))
  }
}

const PREVIEW_DAY = 86_400
const PRESENCE_REQUIRED = 'presenceRequired'
let previewRetentionDays = 180
let previewPresenceAsked = false

function previewReleaseState(): 'entries' | 'empty' | 'unreadable' {
  const requested = typeof window === 'undefined' ? null : new URLSearchParams(window.location.search).get('previewActivity')
  return requested === 'empty' || requested === 'unreadable' ? requested : 'entries'
}

function previewReleaseEntries(): ReleaseEntryView[] {
  const now = Math.floor(Date.now() / 1_000)
  const today = now - (now % PREVIEW_DAY) + 9 * 3_600
  const entry = (seq: number, at: number, partial: Partial<ReleaseEntryView>): ReleaseEntryView => ({
    seq, at, kind: 'browserFill', outcome: 'released', fields: [], count: 1, late: false, ...partial,
  })
  const entries = [
    entry(1, today - 6 * PREVIEW_DAY, { kind: 'browserFill', itemId: 'gmail', itemKind: 'login', host: 'accounts.example.com', fields: ['username', 'password'], matchKind: 'exact' }),
    entry(2, today - 3 * PREVIEW_DAY, { kind: 'csvExport', count: 24 }),
    entry(3, today - PREVIEW_DAY + 1_800, { kind: 'browserFill', itemId: 'github', itemKind: 'login', host: 'example.com', fields: ['username', 'password'], matchKind: 'exact' }),
    entry(4, today - PREVIEW_DAY + 2_400, { kind: 'browserFill', outcome: 'lookalike', host: 'examp1e.com', similarTo: 'example.com' }),
    entry(5, today - PREVIEW_DAY + 9_000, { kind: 'browserTotp', outcome: 'timedOut', host: 'login.example.net' }),
    entry(6, today + 600, { kind: 'copy', itemId: 'gmail', itemKind: 'login', fields: ['password'] }),
    entry(7, today + 1_200, { kind: 'browserFill', outcome: 'denied', host: 'shop.example.org', count: 3 }),
    entry(8, today + 2_400, { kind: 'browserFill', itemId: 'gmail', itemKind: 'login', host: 'accounts.example.com', fields: ['username', 'password'], matchKind: 'site' }),
    entry(9, today + 3_000, { kind: 'reveal', itemId: 'github', itemKind: 'login', fields: ['password'] }),
    entry(11, today - PREVIEW_DAY + 12_000, { kind: 'reveal', itemId: 'gmail', itemKind: 'login', fields: ['password'], host: 'terminal' }),
    entry(12, today - PREVIEW_DAY + 12_600, { kind: 'copy', itemId: 'github', itemKind: 'login', fields: ['twoFactorCode'], host: 'terminal' }),
  ]
  if (previewReleaseState() === 'unreadable') entries.push(entry(10, today - 2 * PREVIEW_DAY, { kind: 'unreadable', outcome: 'noted', count: 4 }))
  return entries.filter((item) => item.at <= now).sort((left, right) => right.at - left.at || right.seq - left.seq)
}

function previewReleaseStatus(entries: ReleaseEntryView[]): ReleaseRecordStatus {
  const state = previewReleaseState()
  const starts = entries.length ? Math.min(...entries.map((item) => item.at)) : undefined
  return {
    available: true,
    entryCount: entries.length,
    startsAt: starts,
    completeSince: state === 'unreadable' ? entries.find((item) => item.kind === 'unreadable')?.at : starts,
    retentionDays: previewRetentionDays,
    unwritten: 0,
    notice: state === 'unreadable' ? 'unreadable' : undefined,
  }
}

export async function getReleaseRecord(query: Partial<ReleaseRecordQuery> = {}): Promise<ReleaseRecordPage> {
  if (previewMode) {
    const all = previewReleaseState() === 'empty' ? [] : previewReleaseEntries()
    const matching = all
      .filter((item) => !query.itemId || item.itemId === query.itemId)
      .filter((item) => !query.refusedOnly || !['released', 'saved', 'updated', 'noted'].includes(item.outcome))
    const offset = query.offset ?? 0
    return { entries: matching.slice(offset, offset + (query.limit ?? 200)), total: matching.length, status: previewReleaseStatus(all) }
  }
  return invoke<ReleaseRecordPage>('get_release_record', { query })
}

export async function getReleaseRecordStatus(): Promise<ReleaseRecordStatus> {
  if (previewMode) return previewReleaseStatus(previewReleaseState() === 'empty' ? [] : previewReleaseEntries())
  return invoke<ReleaseRecordStatus>('get_release_record_status')
}

export async function onReleaseRecordChanged(handler: (status: ReleaseRecordStatus) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<ReleaseRecordStatus>('release-record-changed', ({ payload }) => handler(payload))
}

export const PREVIEW_APPROVAL_ID = 'preview-approval'

export function previewBrowserFillRequest(): BrowserFillRequest | null {
  if (!previewMode || typeof window === 'undefined') return null
  if (new URLSearchParams(window.location.search).get('previewApproval') !== 'fill') return null
  return {
    approvalId: PREVIEW_APPROVAL_ID,
    origin: 'https://accounts.example.com',
    hostname: 'accounts.example.com',
    candidates: [
      { id: 'gmail', title: 'Gmail', username: 'hello@example.test', email: '', savedOrigin: 'https://accounts.example.com', matchKind: 'exact' },
      { id: 'github', title: 'GitHub', username: 'sesame-preview', email: '', savedOrigin: 'https://accounts.example.com', matchKind: 'exact' },
    ],
    expiresInSeconds: 600,
    expiresAtUnixMs: Date.now() + 600_000,
  }
}

export async function getReleaseRecordHint(approvalId: string): Promise<ReleaseRecordHint | null> {
  if (previewMode) {
    if (approvalId !== PREVIEW_APPROVAL_ID) return null
    const now = Math.floor(Date.now() / 1_000)
    return {
      approvalId,
      host: 'accounts.example.com',
      items: [
        { itemId: 'gmail', releasedHere: 12, lastReleasedAt: now - 3 * PREVIEW_DAY },
        { itemId: 'github', releasedHere: 0 },
      ],
      recordSince: now - 90 * PREVIEW_DAY,
      incomplete: false,
      deniedRecently: 1,
      lastDeniedAt: now - 2 * PREVIEW_DAY,
    }
  }
  return invoke<ReleaseRecordHint | null>('get_release_record_hint', { approvalId })
}


export async function setReleaseRecordRetention(days: number): Promise<ReleaseRecordStatus> {
  if (previewMode) {
    if (days < previewRetentionDays && !previewPresenceAsked) {
      previewPresenceAsked = true
      throw new Error(PRESENCE_REQUIRED)
    }
    previewPresenceAsked = false
    previewRetentionDays = days
    return { ...(await getReleaseRecordStatus()), retentionDays: days }
  }
  return invoke<ReleaseRecordStatus>('set_release_record_retention', { days })
}

export async function clearReleaseRecord(): Promise<ReleaseRecordStatus> {
  if (previewMode) return { ...(await getReleaseRecordStatus()), retentionDays: previewRetentionDays }
  return invoke<ReleaseRecordStatus>('clear_release_record')
}

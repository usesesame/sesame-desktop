import { writable } from 'svelte/store'
import type { EntryKind, FieldKind, MatchKind, Outcome, ReleaseEntryView, ReleaseRecordHint, ReleaseRecordStatus } from './types'

export type TitleLookup = (itemKind: string, itemId: string) => string | null

const RELEASED: Outcome[] = ['released', 'saved', 'updated', 'noted']

export function isRefusal(outcome: Outcome): boolean {
  return !RELEASED.includes(outcome)
}

const fieldNames: Record<FieldKind, string> = {
  password: 'password',
  username: 'username',
  email: 'email',
  twoFactorCode: 'one-time code',
  backupCodes: 'backup codes',
  customField: 'hidden field',
  legacyField: 'saved field',
  cardNumber: 'card number',
  cardholderName: 'cardholder name',
  cardExpiry: 'expiry date',
  securityCode: 'security code',
  fullName: 'full name',
  phone: 'phone number',
  address: 'address',
  privateKey: 'private key',
  publicKey: 'public key',
  passphrase: 'passphrase',
  licenseKey: 'licence key',
  documentNumber: 'document number',
  noteContent: 'note',
  other: 'field',
}

const itemNouns: Record<string, string> = {
  login: 'login',
  identity: 'identity',
  secure_note: 'note',
  card: 'card',
  wifi_network: 'Wi-Fi network',
  ssh_key: 'SSH key',
  software_license: 'licence',
  document: 'document',
  custom_record: 'record',
}

const requestNouns: Partial<Record<EntryKind, string>> = {
  browserFill: 'login fill',
  browserSave: 'login save',
  browserTotp: 'one-time code fill',
  browserCard: 'card fill',
  browserIdentity: 'identity fill',
  browserChange: 'password change',
  browserCreate: 'new login',
}

function article(noun: string): string {
  return /^[aeiu]|^o(?!ne)/i.test(noun) ? `an ${noun}` : `a ${noun}`
}

function joinWords(words: string[]): string {
  if (words.length <= 1) return words[0] ?? ''
  return `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`
}

export function fieldList(fields: FieldKind[]): string {
  return joinWords(fields.map((field) => fieldNames[field]))
}

export function itemNoun(itemKind: string): string {
  return itemNouns[itemKind] ?? 'item'
}

export function thisItem(itemKind: string): string {
  return `this ${itemNoun(itemKind)}`
}

export const activityItemFilter = writable<{ itemId: string; itemKind: string } | null>(null)

export function itemTitle(entry: Pick<ReleaseEntryView, 'itemId' | 'itemKind'>, titleFor: TitleLookup): string {
  const kind = entry.itemKind ?? ''
  const found = entry.itemId ? titleFor(kind, entry.itemId) : null
  if (found) return found
  return `a removed ${itemNouns[kind] ?? 'item'}`
}

function browserSentence(entry: ReleaseEntryView, titleFor: TitleLookup): string {
  const noun = requestNouns[entry.kind] ?? 'browser'
  const host = entry.host ?? 'an unknown site'
  const title = itemTitle(entry, titleFor)
  switch (entry.outcome) {
    case 'released':
      if (entry.kind === 'browserTotp') return `Filled the one-time code for ${title} on ${host}`
      return `Filled ${title} on ${host}`
    case 'saved':
      return `Saved ${title} from ${host}`
    case 'updated':
      return `Updated the password for ${title} from ${host}`
    case 'denied':
      return `You denied ${article(noun)} request from ${host}`
    case 'timedOut':
      return `${capitalise(article(noun))} request from ${host} was not answered in time`
    case 'connectionClosed':
      return `The browser closed ${article(noun)} request from ${host} before it finished`
    case 'vaultChanged':
      return `${capitalise(article(noun))} request from ${host} stopped because the vault changed`
    case 'withdrawn':
      return `Sesame cancelled ${article(noun)} request from ${host}`
    case 'lookalike':
      return entry.similarTo
        ? `Sesame refused ${article(noun)} on ${host} because it looks like ${entry.similarTo}`
        : `Sesame refused ${article(noun)} on ${host} because it looks like a saved site`
    case 'noMatch':
      return `No saved item matched ${article(noun)} request from ${host}`
    case 'locked':
      return `${capitalise(article(noun))} request from ${host} arrived while Sesame was locked`
    case 'busy':
      return `Sesame refused ${article(noun)} request from ${host} while another request was open`
    case 'mismatch':
      return `Sesame refused ${article(noun)} on ${host} because the choice did not match what it offered`
    case 'replayed':
      return `Sesame refused a repeated ${noun} request from ${host}`
    case 'neverSave':
      return `Sesame did not save a login from ${host} because the site is on the never save list`
    default:
      return `${capitalise(article(noun))} request came from ${host}`
  }
}

function capitalise(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1)
}

export const TERMINAL_HOST = 'terminal'

function fromTerminal(entry: ReleaseEntryView): boolean {
  return entry.host === TERMINAL_HOST && (entry.kind === 'reveal' || entry.kind === 'copy')
}

export function entrySentence(entry: ReleaseEntryView, titleFor: TitleLookup): string {
  if (requestNouns[entry.kind]) return browserSentence(entry, titleFor)
  const title = itemTitle(entry, titleFor)
  const fields = fieldList(entry.fields) || 'secret'
  switch (entry.kind) {
    case 'reveal':
      return fromTerminal(entry) ? `Read the ${fields} of ${title} for a terminal` : `Showed the ${fields} of ${title}`
    case 'copy':
      return fromTerminal(entry) ? `Copied the ${fields} of ${title} for a terminal` : `Copied the ${fields} of ${title}`
    case 'autoType':
      return `Typed the ${fields} of ${title} into another window`
    case 'quickAccess':
      return `Copied the ${fields} of ${title} from quick access`
    case 'csvExport':
      return `Exported ${entry.count} ${entry.count === 1 ? 'item' : 'items'} to a readable CSV file`
    case 'jsonExport':
      return `Exported ${entry.count} ${entry.count === 1 ? 'item' : 'items'} to a readable JSON file`
    case 'backupExport':
      return 'Saved an encrypted backup to a folder you chose'
    case 'backupCreated':
      return 'Made an encrypted backup on this device'
    case 'recoveryKitSaved':
      return 'Saved the recovery kit to a file'
    case 'attachmentSaved':
      return `Saved an attachment from ${title} to a file`
    case 'devicePaired':
      return 'Gave the vault key to a new device through Sync'
    case 'emailAlias': {
      const host = entry.host ?? 'the alias service'
      if (entry.outcome === 'withdrawn') return `Sesame tried to make a new alias but did not send your API token to ${host}`
      if (entry.outcome === 'connectionClosed') return `Sesame may have sent your alias API token to ${host}, but the connection ended before an answer`
      return `Sent your alias API token to ${host} to make a new alias`
    }
    case 'cleared':
      return 'The activity record was cleared'
    case 'retentionShortened':
      return 'You shortened how long Sesame keeps activity'
    case 'unreadable':
      return 'Sesame could not read part of the activity record'
    case 'interrupted':
      return 'An entry was cut off while Sesame was writing it'
    case 'fileChanged':
      return 'The activity file changed outside Sesame, so Sesame wrote it again'
    case 'lockedOverflow':
      return 'More requests arrived while Sesame was locked than it could keep'
    case 'refusalLimit':
      return 'Some refused requests were counted but not listed one by one'
    case 'writesLost':
      return 'Some entries could not be written and were lost'
    case 'newer':
      return 'Something a newer version of Sesame recorded'
    default:
      return 'Sesame recorded an event'
  }
}

const matchNotes: Record<MatchKind, string | null> = {
  exact: null,
  wwwAlias: 'Matched without www',
  site: 'Matched by site',
}

export function entryTime(at: number): string {
  return new Date(at * 1_000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

const COUNTED_REQUESTS: EntryKind[] = ['lockedOverflow', 'refusalLimit', 'writesLost']
const COUNTED_ITEMS: EntryKind[] = ['csvExport', 'jsonExport']

export function entryDetails(entry: ReleaseEntryView, withDate = false): string {
  const parts = [withDate ? `${shortDate(entry.at)} at ${entryTime(entry.at)}` : entryTime(entry.at)]
  const note = entry.matchKind ? matchNotes[entry.matchKind] : null
  if (note) parts.push(note)
  if (entry.kind === 'cleared' || entry.kind === 'retentionShortened') parts.push(`${entry.count} ${entry.count === 1 ? 'entry' : 'entries'} removed`)
  else if (entry.kind === 'unreadable') {
    if (entry.count > 1) parts.push(`${entry.count} entries lost`)
  } else if (COUNTED_REQUESTS.includes(entry.kind)) parts.push(`${entry.count} ${entry.count === 1 ? 'request' : 'requests'}`)
  else if (!COUNTED_ITEMS.includes(entry.kind) && entry.count > 1) parts.push(`${entry.count} times`)
  if (entry.late) parts.push('Written later')
  return parts.join(' · ')
}

function startOfDay(at: number): number {
  const date = new Date(at * 1_000)
  date.setHours(0, 0, 0, 0)
  return date.getTime()
}

export function dayLabel(at: number, now = Date.now() / 1_000): string {
  const day = startOfDay(at)
  const today = startOfDay(now)
  if (day === today) return 'Today'
  if (today - day === 86_400_000) return 'Yesterday'
  const sameYear = new Date(day).getFullYear() === new Date(today).getFullYear()
  return new Date(day).toLocaleDateString(undefined, sameYear
    ? { weekday: 'long', day: 'numeric', month: 'long' }
    : { day: 'numeric', month: 'long', year: 'numeric' })
}

export interface ReleaseDay {
  key: number
  label: string
  entries: ReleaseEntryView[]
}

export function groupByDay(entries: ReleaseEntryView[], now = Date.now() / 1_000): ReleaseDay[] {
  const days: ReleaseDay[] = []
  for (const entry of entries) {
    const key = startOfDay(entry.at)
    const last = days[days.length - 1]
    if (last && last.key === key) last.entries.push(entry)
    else days.push({ key, label: dayLabel(entry.at, now), entries: [entry] })
  }
  return days
}

export function longDate(at: number): string {
  return new Date(at * 1_000).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' })
}

export function statusNotice(status: ReleaseRecordStatus | null): string | null {
  if (!status) return null
  if (status.unwritten > 0) {
    return `Sesame could not write ${status.unwritten === 1 ? 'one entry' : `${status.unwritten} entries`} to the activity record. It keeps ${status.unwritten === 1 ? 'it' : 'them'} in memory and will try again, but the record is incomplete until then.`
  }
  if (status.notice === 'unreadable') {
    return 'Sesame could not read part of the activity record, so it kept what it could read and started a new record. This can happen after a master password change if Sesame closed before it finished, or after restoring an older backup.'
  }
  if (status.notice === 'interrupted') return 'Sesame was interrupted while writing the last entry, so that entry is missing.'
  if (status.notice === 'fileChanged') return 'The activity file changed while Sesame was running, so Sesame wrote it again from what it had in memory.'
  return null
}

export const RECORD_SCOPE_TEXT = [
  'Sesame lists every time a password or other secret leaves your vault, and every browser request it turned down.',
  'The list is encrypted, stays on this device, and drops entries older than the time you choose above.',
  'It leaves out one-time codes you only look at and breach checks.',
  'Another program on this computer could change or delete the list, so use it as a guide.',
]

export function shortDate(at: number, now = Date.now() / 1_000): string {
  const sameYear = new Date(at * 1_000).getFullYear() === new Date(now * 1_000).getFullYear()
  return new Date(at * 1_000).toLocaleDateString(undefined, sameYear ? { day: 'numeric', month: 'long' } : { day: 'numeric', month: 'long', year: 'numeric' })
}

export function hintLine(hint: ReleaseRecordHint | null, itemId: string, noun: string, now = Date.now() / 1_000): string | null {
  if (!hint || !itemId) return null
  if (hint.incomplete) return 'The activity record is incomplete, so Sesame cannot say how often this was filled here.'
  const item = hint.items.find((candidate) => candidate.itemId === itemId)
  if (!item) return null
  if (item.releasedHere === 0 || !item.lastReleasedAt) {
    return `Sesame has no record of filling this ${noun} on ${hint.host} since ${shortDate(hint.recordSince, now)}.`
  }
  return `Filled here ${item.releasedHere} ${item.releasedHere === 1 ? 'time' : 'times'}, last on ${shortDate(item.lastReleasedAt, now)}.`
}

export function cautionLine(hint: ReleaseRecordHint | null, now = Date.now() / 1_000): string | null {
  if (!hint || hint.deniedRecently < 1 || !hint.lastDeniedAt) return null
  if (hint.deniedRecently === 1) return `You denied a request from this site on ${shortDate(hint.lastDeniedAt, now)}.`
  return `You denied ${hint.deniedRecently} requests from this site in the last two weeks, most recently on ${shortDate(hint.lastDeniedAt, now)}.`
}

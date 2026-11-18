import type { CliApprovalRequestEvent } from './generated/CliApprovalRequestEvent'
import type { CliUnlockRequestEvent } from './generated/CliUnlockRequestEvent'
import { itemNoun } from './release-record'

export const MAX_SHOWN_CHARS = 80

export const MAX_MARKS_PER_CHARACTER = 2
export const UNREADABLE_NAME = 'Unreadable name'
export const STAND_IN = '?'

const HIDDEN_FORMATTING = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}\p{Default_Ignorable_Code_Point}]/u
const SPACES = /\p{Zs}/u
const MARK = /\p{M}/u
const BLANK_LOOKING_POINTS = new Set([0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180e, 0x180f, 0x2800, 0x3164, 0xffa0, 0x1d159, 0x1d173, 0x1d174, 0x1d175, 0x1d176, 0x1d177, 0x1d178, 0x1d179, 0x1d17a])
const BLANK_LOOKING = { test: (character: string) => BLANK_LOOKING_POINTS.has(character.codePointAt(0) ?? 0) }
const READABLE = /[^?\s]/u

function cleaned(value: string): string[] {
  const out: string[] = []
  let marks = 0
  let excess = false
  for (const character of value.normalize('NFC')) {
    if (BLANK_LOOKING.test(character) || HIDDEN_FORMATTING.test(character)) {
      out.push(STAND_IN)
      marks = 0
      excess = false
    } else if (MARK.test(character)) {
      if (out.length === 0 || out[out.length - 1] === ' ' || out[out.length - 1] === STAND_IN) {
        if (!excess) out.push(STAND_IN)
        excess = true
      } else if (marks < MAX_MARKS_PER_CHARACTER) {
        out[out.length - 1] += character
        marks += 1
      } else if (!excess) {
        out.push(STAND_IN)
        excess = true
      }
    } else {
      out.push(SPACES.test(character) ? ' ' : character)
      marks = 0
      excess = false
    }
  }
  return out
}

function codePoints(unit: string): number {
  return [...unit].length
}

function capped(units: string[], max: number): string {
  const joined = units.join('')
  if (codePoints(joined) <= max) return joined
  if (max < 1) return ''
  let kept = ''
  let used = 0
  for (const unit of units) {
    const size = codePoints(unit)
    if (used + size > max - 1) break
    kept += unit
    used += size
  }
  return `${kept}…`
}

export function shownText(value: string | null | undefined, max = MAX_SHOWN_CHARS): string {
  const plain = cleaned(value ?? '')
  if (!READABLE.test(plain.join(''))) return capped([...UNREADABLE_NAME], max)
  return capped(plain, max)
}

const knownFields: Record<string, string> = {
  password: 'password',
  username: 'username',
  email: 'email address',
  url: 'website address',
  notes: 'notes',
  backupCodes: 'backup codes',
  number: 'card number',
  securityCode: 'security code',
  cardholderName: 'cardholder name',
  privateKey: 'private key',
  publicKey: 'public key',
  passphrase: 'passphrase',
  licenseKey: 'licence key',
  documentNumber: 'document number',
  content: 'note',
  totp: 'one-time code',
}

export function fieldWords(field: string | undefined): string | null {
  if (!field) return null
  return Object.prototype.hasOwnProperty.call(knownFields, field) ? knownFields[field] : null
}

type HeadingRequest = Pick<CliApprovalRequestEvent, 'command' | 'field' | 'copy' | 'fieldHidden'>

export function approvalHeading(request: HeadingRequest): string {
  if (request.command === 'list') return 'A terminal wants the names of all your items'
  if (request.command === 'totp') return request.copy ? 'A terminal wants to copy a one-time code' : 'A terminal wants a one-time code'
  if (!request.field) return 'A terminal wants to read an item'
  const words = fieldWords(request.field)
  const what = words ? `the ${words}` : request.fieldHidden ? 'a hidden field' : 'one field'
  return request.copy ? `A terminal wants to copy ${what} of an item` : `A terminal wants ${what} of an item`
}

export function approvalSummary(request: HeadingRequest): string {
  if (request.command === 'list') return 'Sesame sends the title and kind of every item, and no passwords or other fields.'
  if (request.command === 'totp') {
    return request.copy
      ? 'Sesame copies the current code to the clipboard instead of printing it in the terminal.'
      : 'Sesame prints the current code in the terminal.'
  }
  if (!request.field) return 'Sesame prints the visible fields and only the names of hidden ones.'
  if (request.copy) return 'Sesame copies the value to the clipboard instead of printing it in the terminal.'
  return request.fieldHidden ? 'Sesame prints this hidden value in the terminal.' : 'Sesame prints this value in the terminal.'
}

export function noticeOnly(request: Pick<CliApprovalRequestEvent, 'notFound' | 'missingField'>): boolean {
  return request.notFound !== undefined || request.missingField
}

export function secretNeeded(request: CliApprovalRequestEvent, selectedId: string, presenceGranted: boolean): boolean {
  if (!request.needsPresence || presenceGranted) return false
  if (request.candidates.length <= 1) return true
  return request.candidates.some((candidate) => candidate.id === selectedId && candidate.fieldHidden)
}

export function outputWords(copy: boolean, clearAfterSeconds: number): string {
  return copy ? `Copied to the clipboard and cleared after ${clearAfterSeconds} seconds` : 'Printed in the terminal'
}

export function kindWords(kind: string): string {
  const noun = itemNoun(kind)
  return noun.charAt(0).toUpperCase() + noun.slice(1)
}

const cancelledLines: Record<string, string> = {
  expired: 'The terminal request was not answered in time, so Sesame turned it down.',
  connectionClosed: 'The terminal stopped waiting, so Sesame closed its request.',
  vaultChanged: 'The vault locked or changed, so Sesame closed the terminal request.',
  preempted: 'A browser request needed the window, so Sesame turned the terminal request down. Run the command again when you are done.',
}

export function cancelledLine(reason: string): string {
  return cancelledLines[reason] ?? 'Sesame closed the terminal request.'
}

type UnlockRequest = Pick<CliUnlockRequestEvent, 'command' | 'field' | 'copy'>

export function unlockLine(request: UnlockRequest): string {
  const wanted = approvalHeading({ command: request.command, field: request.field, copy: request.copy, fieldHidden: false })
  return `${wanted}. Sesame asks you about it after you unlock.`
}

export function remainingWords(ms: number): string {
  if (ms >= 60_000) {
    const minutes = Math.floor(ms / 60_000)
    return `${minutes} more ${minutes === 1 ? 'minute' : 'minutes'}`
  }
  const seconds = Math.min(59, Math.max(0, Math.ceil(ms / 1_000)))
  return `${seconds} more ${seconds === 1 ? 'second' : 'seconds'}`
}

export function allowedRequestWords(command: string, field: string | undefined, title: string | null, kind: string | undefined): string {
  const item = title ?? (kind ? `a removed ${itemNoun(kind)}` : 'an item')
  if (command === 'list') return 'Listed every item title'
  if (command === 'totp') return `Read the one-time code of ${item}`
  if (!field) return `Read ${item}`
  const words = fieldWords(field)
  return words ? `Read the ${words} of ${item}` : `Read a field of ${item}`
}

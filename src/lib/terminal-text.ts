import type { CliApprovalRequestEvent } from './generated/CliApprovalRequestEvent'
import type { CliCommandKind } from './generated/CliCommandKind'
import { itemNoun } from './release-record'

export const MAX_SHOWN_CHARS = 80

const HIDDEN_FORMATTING = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{Cn}]/u
const SPACES = /\p{Zs}/u

export function shownText(value: string | null | undefined, max = MAX_SHOWN_CHARS): string {
  const plain = [...(value ?? '').normalize('NFC')]
    .map((character) => (HIDDEN_FORMATTING.test(character) ? '?' : SPACES.test(character) ? ' ' : character))
  if (plain.length <= max) return plain.join('')
  return `${plain.slice(0, max - 1).join('')}…`
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

export function commandWords(command: CliCommandKind | string): string {
  if (command === 'list') return 'list every item title'
  if (command === 'totp') return 'read a one-time code'
  if (command === 'get') return 'read an item'
  return 'make a request'
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

export function unlockLine(command: CliCommandKind): string {
  return `A terminal is waiting to ${commandWords(command)}. Sesame asks you about it after you unlock.`
}

export function remainingWords(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1_000))
  if (seconds >= 60) {
    const minutes = Math.ceil(seconds / 60)
    return `${minutes} more ${minutes === 1 ? 'minute' : 'minutes'}`
  }
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

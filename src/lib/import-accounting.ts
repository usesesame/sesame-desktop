import type { ImportAccounting, ImportItemReason, ImportSource } from './types'

export const authenticatorSources: ImportSource[] = ['otpauth-txt', 'aegis-json', '2fas-json']

export function isAuthenticatorSource(source: ImportSource) {
  return authenticatorSources.includes(source)
}

const reasonLabels: Record<ImportItemReason, string> = {
  counterBasedCode: 'Counter-based codes (HOTP)',
  steamCode: 'Steam Guard codes',
  unsupportedCodeType: 'Codes of a type Sesame does not support',
  transferLink: 'Transfer links, which can hold several codes each',
  unsupportedItemType: 'Items of a type Sesame cannot import yet',
  unsupportedAlgorithm: 'Codes that use a hash algorithm Sesame does not support',
  unknownAlgorithm: 'Codes with a hash algorithm Sesame does not recognise',
  unusableCode: 'Codes whose secret or settings produce no code',
  missingCredentials: 'Rows with no name, username or password',
  unreadableRow: 'Rows Sesame could not read',
}

const unsupportedReasons: ImportItemReason[] = ['counterBasedCode', 'steamCode', 'unsupportedCodeType', 'transferLink', 'unsupportedItemType', 'unsupportedAlgorithm']
const malformedReasons: ImportItemReason[] = ['unknownAlgorithm', 'unusableCode', 'missingCredentials', 'unreadableRow']

export interface AccountingReason {
  reason: ImportItemReason
  label: string
  count: number
}

export interface AccountingGroup {
  key: 'accepted' | 'retained' | 'unsupported' | 'malformed'
  label: string
  count: number
  reasons: AccountingReason[]
}

function reasonRows(accounting: ImportAccounting, order: ImportItemReason[]): AccountingReason[] {
  return order.flatMap((reason) => {
    const count = accounting.reasons.filter((known) => known.reason === reason).reduce((sum, known) => sum + known.count, 0)
    return count > 0 ? [{ reason, label: reasonLabels[reason], count }] : []
  })
}

export function accountingGroups(accounting: ImportAccounting): AccountingGroup[] {
  const groups: AccountingGroup[] = [
    { key: 'accepted', label: 'Added to your vault', count: accounting.accepted, reasons: [] },
    { key: 'retained', label: 'Added, with extra fields kept in Legacy data', count: accounting.retained, reasons: [] },
    { key: 'unsupported', label: 'Not supported by Sesame yet', count: accounting.unsupported, reasons: reasonRows(accounting, unsupportedReasons) },
    { key: 'malformed', label: 'Could not be read', count: accounting.malformed, reasons: reasonRows(accounting, malformedReasons) },
  ]
  return groups.filter((group) => group.key === 'accepted' || group.count > 0)
}

export function omittedCount(accounting: ImportAccounting) {
  return accounting.unsupported + accounting.malformed
}

export function keepSourceNote(accounting: ImportAccounting, authenticator: boolean) {
  const omitted = omittedCount(accounting)
  if (omitted === 0) return ''
  const single = omitted === 1
  const noun = authenticator ? 'code' : 'item'
  const owner = authenticator ? 'authenticator' : 'password manager'
  const next = authenticator
    ? `set ${single ? 'that code' : 'those codes'} up again`
    : `saved ${single ? 'that item' : 'those items'} somewhere else`
  return `Sesame will not add ${single ? `1 ${noun}` : `${omitted} ${noun}s`}, so ${single ? 'it exists' : 'they exist'} only in your old ${owner}. Keep it until you have ${next}.`
}

export function accountingNoun(authenticator: boolean, count: number) {
  const noun = authenticator ? 'code' : 'item'
  return count === 1 ? noun : `${noun}s`
}

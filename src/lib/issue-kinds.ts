import type { IssueKind } from './types'

export const issueKindLabels: Record<IssueKind, { title: string; summary: string; filter: string }> = {
  duplicate: { title: 'Duplicates', summary: 'possible duplicate', filter: 'duplicates' },
  'weak-password': { title: 'Weak passwords', summary: 'weak password', filter: 'weak passwords' },
  'common-password': { title: 'Common passwords', summary: 'common password', filter: 'common passwords' },
  'reused-password': { title: 'Reused passwords', summary: 'reused password', filter: 'reused passwords' },
  'compromised-pattern': { title: 'Known compromised patterns', summary: 'unsafe password pattern', filter: 'unsafe password patterns' },
  'old-password': { title: 'Old passwords', summary: 'not changed in over a year', filter: 'passwords not changed in over a year' },
  url: { title: 'Website address missing', summary: 'website missing', filter: 'logins without a website' },
  totp: { title: 'No 2FA code saved', summary: '2FA not saved', filter: 'missing 2FA' },
  recovery: { title: 'Recovery details to review', summary: 'recovery not reviewed', filter: 'missing recovery details' },
}

export const issueSeverityWeight: Record<IssueKind, number> = {
  'reused-password': 0,
  'compromised-pattern': 1,
  'weak-password': 2,
  'common-password': 3,
  totp: 4,
  recovery: 5,
  'old-password': 6,
  duplicate: 7,
  url: 8,
}

export function issueSummary(issueKinds: IssueKind[]): string {
  return issueKinds.map((issue) => issueKindLabels[issue].summary).join(' · ')
}

export function issueFilterLabel(issue: IssueKind): string {
  return issueKindLabels[issue].filter
}

export function issueChips(issueKinds: IssueKind[], max = 2): { shown: IssueKind[]; extra: number } {
  const unique = issueKinds.filter((kind, index) => issueKinds.indexOf(kind) === index)
  return { shown: unique.slice(0, max), extra: Math.max(0, unique.length - max) }
}

export function issueChipLabel(issue: IssueKind): string {
  return issueKindLabels[issue].summary
}

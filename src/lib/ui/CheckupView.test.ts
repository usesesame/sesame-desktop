/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { BreachScanReport, SecuritySummary, VaultSnapshot } from '../types'
import CheckupView from './CheckupView.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function security(overrides: Partial<SecuritySummary> = {}): SecuritySummary {
  return {
    good: 3,
    needsAttention: 2,
    duplicateCandidates: 0,
    weakOrReused: 1,
    weakPasswords: 1,
    commonPasswords: 0,
    reusedPasswords: 0,
    compromisedPatterns: 0,
    oldPasswords: 0,
    missingUrls: 0,
    noTotp: 1,
    missingRecovery: 0,
    expiredCards: 0,
    expiringCards: 0,
    twoFactorSites: 0,
    twoFactorLogins: [],
    ...overrides,
  }
}

function snapshot(overrides: Partial<SecuritySummary> = {}): VaultSnapshot {
  return {
    vaultName: 'Fictional vault',
    revision: 1,
    folders: [],
    entries: [],
    items: [],
    trash: [],
    history: [],
    security: security(overrides),
  }
}

function checkupProps(overrides: Record<string, unknown> = {}) {
  return {
    snapshot: snapshot(),
    onSelectGroup: vi.fn(),
    onSelectEntry: vi.fn(),
    onEdit: vi.fn(),
    onMerge: vi.fn(),
    onDelete: vi.fn(),
    onOpenDuplicateReview: vi.fn(),
    onShowSecurityFilter: vi.fn(),
    onShowCards: vi.fn(),
    onStartBreachScan: vi.fn(),
    onCancelBreachScan: vi.fn(),
    ...overrides,
  }
}

function renderCheckup(overrides: Record<string, unknown> = {}) {
  const props = checkupProps(overrides)
  const rendered = render(CheckupView, { props } as never)
  return { rendered, props }
}

function rowTitles(rows: Element[]): Array<string | undefined> {
  return rows.map((row) => row.querySelector('h3')?.textContent ?? undefined)
}

function finishedScan(results: BreachScanReport['results']): BreachScanReport {
  return { phase: 'finished', checked: results.length, total: results.length, results }
}

test('the header count is singular for one account and plural for many', async () => {
  const { rendered } = renderCheckup({ snapshot: snapshot({ good: 1 }) })
  await Promise.resolve()
  const aside = rendered.container.querySelector('.view-header-aside') as HTMLElement
  expect(aside.querySelector('strong')?.textContent).toBe('1')
  expect(aside.querySelector('span')?.textContent).toBe('account ready')

  await rendered.rerender({ ...checkupProps({ snapshot: snapshot({ good: 4 }) }) } as never)
  const pluralAside = rendered.container.querySelector('.view-header-aside') as HTMLElement
  expect(pluralAside.querySelector('strong')?.textContent).toBe('4')
  expect(pluralAside.querySelector('span')?.textContent).toBe('accounts ready')
})

test('categories with findings come first and zero-count categories sit in the No issues group', async () => {
  const { rendered } = renderCheckup()
  await Promise.resolve()
  const rows = [...rendered.container.querySelectorAll('.finding-row')]
  const actionable = rows.filter((row) => row.tagName === 'BUTTON')
  const clear = rows.filter((row) => row.closest('.clear-findings'))
  const clearGroup = rendered.container.querySelector('.clear-findings') as HTMLElement

  expect(rowTitles(actionable)).toEqual(['Weak passwords', 'No 2FA code saved'])
  expect(rowTitles(clear)).toEqual([
    'Expired cards',
    'Reused passwords',
    'Known compromised patterns',
    'Common passwords',
    'Cards expiring soon',
    'Recovery details to review',
    'Old passwords',
    'Duplicates',
    'Website address missing',
    'Sites that offer 2FA',
  ])
  for (const row of actionable) {
    expect(row.compareDocumentPosition(clearGroup) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  }
})

test('the No issues group is a native disclosure the keyboard can open', async () => {
  const { rendered } = renderCheckup()
  await Promise.resolve()
  const clearGroup = rendered.container.querySelector('.clear-findings') as HTMLDetailsElement
  const summary = clearGroup.querySelector('summary') as HTMLElement

  expect(clearGroup.open).toBe(false)
  expect(screen.getByText('No issues')).toBeTruthy()
  expect(summary.textContent).toContain('10 categories clear')

  await fireEvent.click(summary)
  expect(clearGroup.open).toBe(true)
})

test('clear rows are not disabled buttons and the summary is the group tab stop', async () => {
  const { rendered } = renderCheckup()
  await Promise.resolve()
  const clearGroup = rendered.container.querySelector('.clear-findings') as HTMLElement
  expect(clearGroup.querySelectorAll('button')).toHaveLength(0)
  expect(clearGroup.querySelector('summary')?.getAttribute('tabindex')).toBeNull()
})

test('expired and expiring cards are separate findings that open the cards list', async () => {
  const { rendered, props } = renderCheckup({ snapshot: snapshot({ expiredCards: 2, expiringCards: 3 }) })
  await Promise.resolve()
  const rows = [...rendered.container.querySelectorAll('.finding-row')] as HTMLElement[]
  const expired = rows.find((row) => row.querySelector('h3')?.textContent === 'Expired cards')
  const expiring = rows.find((row) => row.querySelector('h3')?.textContent === 'Cards expiring soon')

  expect(expired?.classList.contains('danger')).toBe(true)
  expect(expired?.querySelector('strong')?.textContent).toBe('2')
  expect(expiring?.querySelector('strong')?.textContent).toBe('3')
  expect(rowTitles(rows).indexOf('Expired cards')).toBeLessThan(rowTitles(rows).indexOf('Cards expiring soon'))

  await fireEvent.click(expired as HTMLElement)
  expect(props.onShowCards).toHaveBeenCalledTimes(1)
})

test('a bundled 2FA match lists a bounded number of logins', async () => {
  const logins = ['one', 'two', 'three', 'four', 'five'].map((name) => ({
    id: `login-${name}`,
    title: `Fictional ${name}`,
    site: `${name}.example.test`,
  }))
  const { rendered } = renderCheckup({ snapshot: snapshot({ twoFactorSites: 7, twoFactorLogins: logins }) })
  await Promise.resolve()
  const list = rendered.container.querySelector('.finding-logins') as HTMLElement

  expect(list).toBeTruthy()
  expect(list.querySelectorAll('li')).toHaveLength(6)
  expect(list.textContent).toContain('Fictional one')
  expect(list.textContent).toContain('and 2 more')
  const row = [...rendered.container.querySelectorAll('.finding-row')].find((candidate) => candidate.querySelector('h3')?.textContent === 'Sites that offer 2FA')
  expect(row?.querySelector('strong')?.textContent).toBe('7')
})

test('the breach check starts as not-yet-scanned and explains the prefix rule', async () => {
  const { rendered, props } = renderCheckup()
  await Promise.resolve()
  const panel = rendered.container.querySelector('.breach-check') as HTMLElement

  expect(panel.textContent).toContain('Not checked yet.')
  expect(panel.textContent).toContain('five characters')
  expect(panel.textContent).not.toContain('No saved password appears')

  await fireEvent.click(screen.getByRole('button', { name: 'Check saved passwords' }))
  expect(props.onStartBreachScan).toHaveBeenCalledTimes(1)
})

test('a running scan shows progress and can be cancelled', async () => {
  const { rendered, props } = renderCheckup({
    breachScan: { phase: 'running', checked: 2, total: 5, results: [] },
  })
  await Promise.resolve()
  const panel = rendered.container.querySelector('.breach-check') as HTMLElement

  expect(panel.textContent).toContain('Checked 2 of 5 logins')
  expect(panel.querySelector('[role="progressbar"]')?.getAttribute('aria-valuenow')).toBe('2')

  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(props.onCancelBreachScan).toHaveBeenCalledTimes(1)
})

test('a network failure reports unknown instead of safe', async () => {
  const { rendered } = renderCheckup({
    breachScan: finishedScan([
      { id: 'login-a', verdict: 'unknown', count: 0 },
      { id: 'login-b', verdict: 'unknown', count: 0 },
    ]),
  })
  await Promise.resolve()
  const panel = rendered.container.querySelector('.breach-check') as HTMLElement

  expect(panel.textContent).toContain('2 passwords could not be checked')
  expect(panel.textContent).toContain('does not know')
  expect(panel.textContent).not.toContain('No saved password appears')
  expect(panel.textContent).not.toContain('appears in known breaches')
})

test('breached logins are listed while unknown ones are still disclosed', async () => {
  const { rendered } = renderCheckup({
    snapshot: snapshot(),
    breachScan: finishedScan([
      { id: 'login-a', verdict: 'breached', count: 12 },
      { id: 'login-b', verdict: 'unknown', count: 0 },
    ]),
  })
  await Promise.resolve()
  const panel = rendered.container.querySelector('.breach-check') as HTMLElement

  expect(panel.textContent).toContain('1 password appears in known breaches')
  expect(panel.textContent).toContain('1 password could not be checked')
  expect(panel.querySelectorAll('.breach-check-list li')).toHaveLength(1)
})

test('a completed clean scan says no saved password appears, and a cancelled one does not', async () => {
  const { rendered } = renderCheckup({
    breachScan: finishedScan([{ id: 'login-a', verdict: 'safe', count: 0 }]),
  })
  await Promise.resolve()
  expect(screen.getByText('No saved password appears in known breaches.')).toBeTruthy()

  await rendered.rerender({ ...checkupProps({ breachScan: { phase: 'cancelled', checked: 0, total: 2, results: [] } }) } as never)
  expect(screen.getByText('The check stopped before it finished. Nothing was verified.')).toBeTruthy()
  expect(screen.queryByText('No saved password appears in known breaches.')).toBeNull()
})

test('a failed start keeps the error and offers a retry', async () => {
  const { props } = renderCheckup({ breachScanError: 'Unlock your vault before checking saved passwords for breaches.' })
  await Promise.resolve()
  expect(screen.getByRole('alert').textContent).toContain('Unlock your vault')

  await fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
  expect(props.onStartBreachScan).toHaveBeenCalledTimes(1)
})

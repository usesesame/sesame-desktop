/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { SecuritySummary, VaultSnapshot } from '../types'
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
    'Reused passwords',
    'Known compromised patterns',
    'Common passwords',
    'Recovery details to review',
    'Old passwords',
    'Duplicates',
    'Website address missing',
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
  expect(summary.textContent).toContain('7 categories clear')

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

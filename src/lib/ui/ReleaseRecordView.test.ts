/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { ReleaseEntryView, ReleaseRecordPage } from '../types'

const getReleaseRecord = vi.fn()

vi.mock('../release-record-api', () => ({
  getReleaseRecord: (...args: unknown[]) => getReleaseRecord(...args),
  onReleaseRecordChanged: async () => () => {},
  getReleaseRecordStatus: async () => ({ available: true, entryCount: 0, retentionDays: 180, unwritten: 0 }),
}))

import ReleaseRecordView from './ReleaseRecordView.svelte'

const titleFor = (_kind: string, id: string) => (id === 'login-a' ? 'Northwind' : null)

function entry(partial: Partial<ReleaseEntryView>): ReleaseEntryView {
  return { seq: 1, at: Math.floor(Date.now() / 1_000) - 60, kind: 'browserFill', outcome: 'released', fields: [], count: 1, late: false, ...partial }
}

function page(entries: ReleaseEntryView[], partial: Partial<ReleaseRecordPage['status']> = {}): ReleaseRecordPage {
  return { entries, total: entries.length, status: { available: true, entryCount: entries.length, startsAt: entries[0]?.at, retentionDays: 180, unwritten: 0, ...partial } }
}

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} })
  getReleaseRecord.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  document.body.replaceChildren()
})

test('the timeline shows sentences grouped under a day heading', async () => {
  getReleaseRecord.mockResolvedValue(page([
    entry({ seq: 2, itemId: 'login-a', itemKind: 'login', host: 'example.com' }),
    entry({ seq: 1, outcome: 'denied', host: 'shop.example.org' }),
  ]))
  render(ReleaseRecordView, { titleFor })

  expect(await screen.findByText('Filled Northwind on example.com')).toBeTruthy()
  expect(screen.getByText('You denied a login fill request from shop.example.org')).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Today' })).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Activity' })).toBeTruthy()
  expect(screen.getByText('About this list')).toBeTruthy()
})

test('an entry from a newer version shows as one plain row that opens nothing', async () => {
  getReleaseRecord.mockResolvedValue(page([entry({ kind: 'newer', outcome: 'noted' })]))
  const onOpenItem = vi.fn()
  render(ReleaseRecordView, { titleFor, onOpenItem })

  expect(await screen.findByText('Something a newer version of Sesame recorded')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /newer version/ })).toBeNull()
  expect(document.querySelector('.activity-row.refused')).toBeNull()
})

test('opening a row with a known item goes to that item', async () => {
  getReleaseRecord.mockResolvedValue(page([entry({ itemId: 'login-a', itemKind: 'login', host: 'example.com' })]))
  const onOpenItem = vi.fn()
  render(ReleaseRecordView, { titleFor, onOpenItem })

  await fireEvent.click(await screen.findByRole('button', { name: /Filled Northwind/ }))
  expect(onOpenItem).toHaveBeenCalledWith('login-a')
})

test('an empty record says so plainly', async () => {
  getReleaseRecord.mockResolvedValue(page([]))
  render(ReleaseRecordView, { titleFor })
  expect(await screen.findByText('Nothing has left the vault since the record began.')).toBeTruthy()
})

test('an unreadable record shows its notice', async () => {
  getReleaseRecord.mockResolvedValue(page([entry({ kind: 'unreadable', outcome: 'noted' })], { notice: 'unreadable' }))
  render(ReleaseRecordView, { titleFor })
  const notice = await screen.findByRole('status')
  expect(notice.textContent).toContain('could not read part of the activity record')
})

test('the filter asks only for refused and unanswered requests', async () => {
  getReleaseRecord.mockResolvedValue(page([entry({})]))
  render(ReleaseRecordView, { titleFor })
  await waitFor(() => expect(getReleaseRecord).toHaveBeenCalledTimes(1))
  await fireEvent.click(screen.getByRole('button', { name: /All activity/ }))
  await fireEvent.click(screen.getByRole('option', { name: 'Refused and unanswered' }))
  await waitFor(() => expect(getReleaseRecord).toHaveBeenLastCalledWith(expect.objectContaining({ refusedOnly: true })))
})

test('the choices for keeping and clearing the list sit on the Activity page', async () => {
  getReleaseRecord.mockResolvedValue(page([entry({ itemId: 'login-a', itemKind: 'login', host: 'example.com' })]))
  render(ReleaseRecordView, { titleFor })
  await waitFor(() => expect(screen.getByText('Keep activity for')).toBeTruthy())
  expect(screen.getByRole('button', { name: 'Clear' })).toBeTruthy()
})

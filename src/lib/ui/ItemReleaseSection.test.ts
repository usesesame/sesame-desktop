/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { ReleaseEntryView } from '../types'

const getReleaseRecord = vi.fn()

vi.mock('../release-record-api', () => ({
  getReleaseRecord: (...args: unknown[]) => getReleaseRecord(...args),
  onReleaseRecordChanged: async () => () => {},
}))

import ItemReleaseSection from './ItemReleaseSection.svelte'

function entry(partial: Partial<ReleaseEntryView>): ReleaseEntryView {
  return { seq: 1, at: Math.floor(Date.now() / 1_000) - 60, kind: 'browserFill', outcome: 'released', itemId: 'login-a', itemKind: 'login', fields: [], count: 1, late: false, ...partial }
}

beforeEach(() => getReleaseRecord.mockReset())

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

test('the item section lists recent releases of this item only', async () => {
  getReleaseRecord.mockResolvedValue({ entries: [entry({ host: 'example.com' })], total: 9, status: { available: true, entryCount: 9, retentionDays: 180, unwritten: 0 } })
  const onShowAll = vi.fn()
  render(ItemReleaseSection, { itemId: 'login-a', itemKind: 'login', onShowAll })

  expect(await screen.findByText('Filled this login on example.com')).toBeTruthy()
  expect(getReleaseRecord).toHaveBeenCalledWith({ itemId: 'login-a', limit: 5 })
  await fireEvent.click(screen.getByRole('button', { name: 'Show all' }))
  expect(onShowAll).toHaveBeenCalledWith('login-a', 'login')
})

test('an item with no releases says so in a sentence', async () => {
  getReleaseRecord.mockResolvedValue({ entries: [], total: 0, status: { available: true, entryCount: 0, retentionDays: 180, unwritten: 0 } })
  render(ItemReleaseSection, { itemId: 'card-a', itemKind: 'card' })
  expect(await screen.findByText('Sesame has not released this card since the activity record began.')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Show all' })).toBeNull()
})

/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const getReleaseRecordStatus = vi.fn()
const setReleaseRecordRetention = vi.fn()

vi.mock('../release-record-api', () => ({
  getReleaseRecordStatus: (...args: unknown[]) => getReleaseRecordStatus(...args),
  setReleaseRecordRetention: (...args: unknown[]) => setReleaseRecordRetention(...args),
}))

import ReleaseRecordSetting from './ReleaseRecordSetting.svelte'

const status = (retentionDays: number) => ({ available: true, entryCount: 4, retentionDays, unwritten: 0 })

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} })
  getReleaseRecordStatus.mockReset().mockResolvedValue(status(180))
  setReleaseRecordRetention.mockReset().mockImplementation(async (days: number) => status(days))
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  document.body.replaceChildren()
})

test('choosing a retention period saves it', async () => {
  render(ReleaseRecordSetting, { onClear: async () => {} })
  await waitFor(() => expect(screen.getByRole('button', { name: '180 days' }).getAttribute('aria-pressed')).toBe('true'))
  await fireEvent.click(screen.getByRole('button', { name: '90 days' }))
  expect(setReleaseRecordRetention).toHaveBeenCalledWith(90)
  await waitFor(() => expect(screen.getByRole('button', { name: '90 days' }).getAttribute('aria-pressed')).toBe('true'))
})

test('clearing asks first and closes the question once the record is cleared', async () => {
  const onClear = vi.fn(async (done: () => void) => done())
  render(ReleaseRecordSetting, { onClear })
  await fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
  expect(screen.getByText('Clear the activity record?')).toBeTruthy()
  expect(onClear).not.toHaveBeenCalled()
  await fireEvent.click(screen.getByRole('button', { name: 'Clear record' }))
  expect(onClear).toHaveBeenCalledTimes(1)
  await waitFor(() => expect(screen.queryByText('Clear the activity record?')).toBeNull())
})

test('cancelling the question clears nothing', async () => {
  const onClear = vi.fn(async () => {})
  render(ReleaseRecordSetting, { onClear })
  await fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(onClear).not.toHaveBeenCalled()
  expect(screen.getByText('Clear activity')).toBeTruthy()
})

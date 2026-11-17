/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const getReleaseRecordStatus = vi.fn()

vi.mock('../release-record-api', () => ({
  getReleaseRecordStatus: (...args: unknown[]) => getReleaseRecordStatus(...args),
}))

import ReleaseRecordSetting from './ReleaseRecordSetting.svelte'

const status = (retentionDays: number) => ({ available: true, entryCount: 4, retentionDays, unwritten: 0 })

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} })
  getReleaseRecordStatus.mockReset().mockResolvedValue(status(180))
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  document.body.replaceChildren()
})

const saved = vi.fn(async (days: number, done: (value: ReturnType<typeof status>) => void) => done(status(days)))

test('choosing a retention period saves it', async () => {
  render(ReleaseRecordSetting, { onClear: async () => {}, onSetRetention: saved })
  await waitFor(() => expect(screen.getByRole('button', { name: '180 days' }).getAttribute('aria-pressed')).toBe('true'))
  await fireEvent.click(screen.getByRole('button', { name: '90 days' }))
  expect(saved).toHaveBeenCalledWith(90, expect.any(Function))
  await waitFor(() => expect(screen.getByRole('button', { name: '90 days' }).getAttribute('aria-pressed')).toBe('true'))
})

test('a shorter period waiting for the master password keeps the current choice', async () => {
  let finish: (() => void) | null = null
  const asking = vi.fn(async (days: number, done: (value: ReturnType<typeof status>) => void) => { finish = () => done(status(days)) })
  render(ReleaseRecordSetting, { onClear: async () => {}, onSetRetention: asking })
  await waitFor(() => expect(screen.getByRole('button', { name: '180 days' }).getAttribute('aria-pressed')).toBe('true'))
  await fireEvent.click(screen.getByRole('button', { name: '30 days' }))
  expect(asking).toHaveBeenCalledWith(30, expect.any(Function))
  expect(screen.getByRole('button', { name: '180 days' }).getAttribute('aria-pressed')).toBe('true')
  expect(screen.getByText(/A shorter time asks for your master password/)).toBeTruthy()
  finish!()
  await waitFor(() => expect(screen.getByRole('button', { name: '30 days' }).getAttribute('aria-pressed')).toBe('true'))
})

test('a refused change shows the reason', async () => {
  render(ReleaseRecordSetting, { onClear: async () => {}, onSetRetention: async () => { throw new Error('Unlock your vault first.') } })
  await waitFor(() => expect(screen.getByRole('button', { name: '180 days' }).getAttribute('aria-pressed')).toBe('true'))
  await fireEvent.click(screen.getByRole('button', { name: '90 days' }))
  await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('Unlock your vault first.'))
})

test('clearing asks first and closes the question once the record is cleared', async () => {
  const onClear = vi.fn(async (done: () => void) => done())
  render(ReleaseRecordSetting, { onClear, onSetRetention: saved })
  await fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
  expect(screen.getByText('Clear the activity record?')).toBeTruthy()
  expect(onClear).not.toHaveBeenCalled()
  await fireEvent.click(screen.getByRole('button', { name: 'Clear record' }))
  expect(onClear).toHaveBeenCalledTimes(1)
  await waitFor(() => expect(screen.queryByText('Clear the activity record?')).toBeNull())
})

test('cancelling the question clears nothing', async () => {
  const onClear = vi.fn(async () => {})
  render(ReleaseRecordSetting, { onClear, onSetRetention: saved })
  await fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(onClear).not.toHaveBeenCalled()
  expect(screen.getByText('Clear activity')).toBeTruthy()
})

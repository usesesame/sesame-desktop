/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'

const getReleaseRecordHint = vi.fn()

vi.mock('../release-record-api', () => ({
  getReleaseRecordHint: (...args: unknown[]) => getReleaseRecordHint(...args),
}))

import ReleaseRecordHintLine from './ReleaseRecordHintLine.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

const now = Math.floor(Date.now() / 1_000)

test('the approval window shows the history of the selected login and a caution', async () => {
  getReleaseRecordHint.mockResolvedValue({
    approvalId: 'approval-1', host: 'example.com', recordSince: now - 90 * 86_400, incomplete: false,
    items: [{ itemId: 'login-a', releasedHere: 12, lastReleasedAt: now - 86_400 }, { itemId: 'login-b', releasedHere: 0 }],
    deniedRecently: 1, lastDeniedAt: now - 2 * 86_400,
  })
  render(ReleaseRecordHintLine, { approvalId: 'approval-1', selectedId: 'login-a', noun: 'login' })

  expect(await screen.findByText(/^Filled here 12 times, last on /)).toBeTruthy()
  expect(screen.getByText(/^You denied a request from this site on /)).toBeTruthy()
  expect(getReleaseRecordHint).toHaveBeenCalledWith('approval-1')
})

test('a hint for another approval is ignored', async () => {
  getReleaseRecordHint.mockResolvedValue({ approvalId: 'other', host: 'example.com', recordSince: now, incomplete: false, items: [{ itemId: 'login-a', releasedHere: 3, lastReleasedAt: now }], deniedRecently: 0 })
  render(ReleaseRecordHintLine, { approvalId: 'approval-1', selectedId: 'login-a', noun: 'login' })
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(screen.queryByText(/Filled here/)).toBeNull()
})

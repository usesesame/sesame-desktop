/* @vitest-environment jsdom */
import { get } from 'svelte/store'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { approvalFooterText, approvalWait } from './approval-wait'

const vaultApi = vi.hoisted(() => ({
  getBrowserApprovalWait: vi.fn(),
}))

vi.mock('./vault', () => ({ ...vaultApi }))

beforeEach(() => {
  vi.useFakeTimers()
  vaultApi.getBrowserApprovalWait.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
})

async function settle() {
  await vi.advanceTimersByTimeAsync(0)
}

test('the approval counts as waiting until the backend reports no wait', async () => {
  vaultApi.getBrowserApprovalWait.mockResolvedValueOnce(750).mockResolvedValue(0)
  const seen: number[] = []
  const stop = approvalWait.subscribe((value) => seen.push(value.ms))

  expect(seen[0]).toBeGreaterThan(0)
  await settle()
  expect(seen.at(-1)).toBe(750)
  await vi.advanceTimersByTimeAsync(100)
  expect(seen.at(-1)).toBe(0)
  stop()
})

test('a focus loss is picked up at once and puts the approval back to waiting', async () => {
  vaultApi.getBrowserApprovalWait.mockResolvedValue(0)
  const stop = approvalWait.subscribe(() => {})
  await settle()
  expect(get(approvalWait).ms).toBe(0)

  vaultApi.getBrowserApprovalWait.mockResolvedValue(750)
  window.dispatchEvent(new Event('blur'))
  await settle()

  expect(get(approvalWait).ms).toBe(750)
  stop()
})

test('an unreadable wait keeps the approval waiting', async () => {
  vaultApi.getBrowserApprovalWait.mockRejectedValue(new Error('unavailable'))
  const stop = approvalWait.subscribe(() => {})
  await settle()

  expect(get(approvalWait).ms).toBeGreaterThan(0)
  stop()
})

test('nothing is polled after the last subscriber leaves', async () => {
  vaultApi.getBrowserApprovalWait.mockResolvedValue(0)
  const stop = approvalWait.subscribe(() => {})
  await settle()
  stop()
  vaultApi.getBrowserApprovalWait.mockClear()

  await vi.advanceTimersByTimeAsync(5_000)
  window.dispatchEvent(new Event('focus'))
  await settle()

  expect(vaultApi.getBrowserApprovalWait).not.toHaveBeenCalled()
})

test('the footer says when approval opens, when to click the window, and how long is left', () => {
  expect(approvalFooterText(20, { ms: 400, windowFocused: true })).toBe('Ready in a moment')
  expect(approvalFooterText(20, { ms: 750, windowFocused: false })).toBe('Click this window to approve')
  expect(approvalFooterText(20, { ms: 0, windowFocused: true })).toBe('Expires in 20s')
  expect(approvalFooterText(0, { ms: 0, windowFocused: true })).toBe('Request expired')
})

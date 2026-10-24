/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import SyncPairingModal from './SyncPairingModal.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

const base = { open: true, phase: 'idle' as const, onClose: vi.fn(), onRetry: vi.fn() }

test('the older key exchange allowance is not offered until a device was refused for it', async () => {
  render(SyncPairingModal, { ...base, error: 'Something else went wrong.', olderKeyRefused: false })
  await Promise.resolve()
  expect(screen.queryByLabelText('Allow a device that only supports the older key exchange.')).toBeNull()
})

test('after a refusal the person can tick the allowance and ask for a new code', async () => {
  render(SyncPairingModal, { ...base, error: 'This device only supports the older key exchange.', olderKeyRefused: true })
  await Promise.resolve()
  const box = screen.getByLabelText('Allow a device that only supports the older key exchange.') as HTMLInputElement
  expect(box.checked).toBe(false)
  box.click()
  await vi.waitFor(() => expect(box.checked).toBe(true))
  expect(screen.getByRole('button', { name: 'Show a new code' })).toBeTruthy()
})

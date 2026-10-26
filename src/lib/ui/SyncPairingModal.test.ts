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

test('while the code is being made it does not claim that pairing could not start', async () => {
  render(SyncPairingModal, { ...base, phase: 'starting' as never })
  await Promise.resolve()
  expect(screen.queryByText('Sesame could not start pairing.')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Show a new code' })).toBeNull()
  expect(screen.getByRole('status').textContent).toContain('Getting a code')
})

test('it says pairing could not start only after a start failed', async () => {
  render(SyncPairingModal, { ...base, phase: 'idle' as const, error: 'Sesame could not reach the service.' })
  await Promise.resolve()
  expect(screen.getByText('Sesame could not start pairing.')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Show a new code' })).toBeTruthy()
})

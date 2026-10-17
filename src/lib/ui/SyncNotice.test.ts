/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import SyncNotice from './SyncNotice.svelte'

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

test('the notice says Sync is off and has had no independent review, and claims nothing else', () => {
  render(SyncNotice, { onKeepOff: vi.fn(), onOpenSettings: vi.fn() })
  expect(screen.getByRole('heading', { name: 'Sesame Sync is off' })).toBeTruthy()
  expect(document.body.textContent).toMatch(/has not had an independent security review/)
  expect(document.body.textContent).toMatch(/Nothing is sent anywhere unless you\s+turn it on/)
  expect(document.body.textContent).not.toMatch(/\b(audited|secure by|production-ready)\b/i)
})

test('keeping Sync off is the focused default and Escape means the same', async () => {
  const onKeepOff = vi.fn()
  render(SyncNotice, { onKeepOff, onOpenSettings: vi.fn() })
  const keepOff = screen.getByRole('button', { name: 'Keep Sync off' })
  await waitFor(() => expect(document.activeElement).toBe(keepOff))
  await fireEvent.click(keepOff)
  expect(onKeepOff).toHaveBeenCalledTimes(1)
  await fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' })
  expect(onKeepOff).toHaveBeenCalledTimes(2)
})

test('Open Sync settings does not turn anything on', async () => {
  const onOpenSettings = vi.fn()
  const onKeepOff = vi.fn()
  render(SyncNotice, { onKeepOff, onOpenSettings })
  await fireEvent.click(screen.getByRole('button', { name: 'Open Sync settings' }))
  expect(onOpenSettings).toHaveBeenCalledTimes(1)
  expect(onKeepOff).not.toHaveBeenCalled()
})

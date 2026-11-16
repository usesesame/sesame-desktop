/* @vitest-environment jsdom */
import { cleanup, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import SyncPanel from './SyncPanel.svelte'

const core = vi.hoisted(() => ({ invoke: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => core)

afterEach(cleanup)

const status = {
  enrolled: true,
  state: 'approved',
  needsNewKey: false,
  alarm: null,
  devices: [{ deviceId: 'd1', label: 'Fictional laptop', state: 'approved', isThisDevice: true, addedIndex: 1, newerKey: true }],
}
const idle = { phase: 'idle', halt: '', conflictRevision: 0, pending: false, lastSuccessRevision: 3, consecutiveFailures: 0, downloadsApplied: 0 }

function answer(coordinator: Record<string, unknown>) {
  core.invoke.mockImplementation(async (command: string) => {
    if (command === 'sync_status') return status
    if (command === 'sync_coordinator_status') return { ...idle, ...coordinator }
    throw new Error(`unexpected ${command}`)
  })
}

test('a stopped Sync says it needs attention instead of calling itself active', async () => {
  answer({ phase: 'halted', halt: 'too_large', vaultBytes: 12 * 1024 * 1024, limitBytes: 10 * 1024 * 1024 })
  render(SyncPanel)
  await waitFor(() => expect(screen.getByText('Needs attention')).toBeTruthy())
  const line = screen.getAllByRole('status')[0].textContent ?? ''
  expect(line).toMatch(/^This vault is 12 MB, and Sesame Sync accepts a vault up to 10 MB\./)
  expect(line).not.toContain('Sync is active')
})

test('a busy server keeps the active summary and says Sesame will try again', async () => {
  answer({ phase: 'busy', retryAfterSeconds: 30, pending: true })
  render(SyncPanel)
  await waitFor(() => expect(screen.getAllByRole('status')[0].textContent).toContain('Sesame will try again shortly.'))
  expect(screen.getByText('Active')).toBeTruthy()
  expect(screen.getAllByRole('status')[0].textContent).toMatch(/^Sync is active/)
})

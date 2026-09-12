/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { BackupCompatibility } from '../types'
import RestoreModal from './RestoreModal.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

function renderRestore(compatibility: BackupCompatibility, overrides: Record<string, unknown> = {}) {
  return render(RestoreModal, {
    restoreSelection: { source: '/tmp/fictional-backup.sesame', fileName: 'fictional-backup.sesame', formatVersion: compatibility === 'current' ? 10 : 8, compatibility, setupComplete: true },
    onClose: vi.fn(),
    onConfirm: vi.fn(),
    ...overrides,
  })
}

test('a current backup asks for its secret and explains the replacement', async () => {
  renderRestore('current')
  await Promise.resolve()
  expect(screen.getByRole('heading', { name: 'Replace the current vault?' })).toBeTruthy()
  expect(screen.getByText('Sesame format 10')).toBeTruthy()
  expect(screen.getByText(/saved to the local backup folder first/)).toBeTruthy()
  expect(screen.getByLabelText("This backup's master password or recovery kit")).toBeTruthy()
  const secret = screen.getByLabelText("This backup's master password or recovery kit") as HTMLInputElement
  await vi.waitFor(() => expect(document.activeElement).toBe(secret))
})

test('an older backup explains the upgrade and that the selected file stays unchanged', async () => {
  renderRestore('upgrade', { replacesVault: false })
  await Promise.resolve()
  expect(screen.getByText('Older Sesame format 8')).toBeTruthy()
  expect(screen.getByText(/upgrades a copy of this older format/)).toBeTruthy()
  expect(screen.getByText(/The selected file is not changed/)).toBeTruthy()
  expect(screen.getByText('Keep the original file until the restore finishes.')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Restore backup' })).toBeTruthy()
})

test('a newer backup names the update action and offers no restore form', async () => {
  renderRestore('newer')
  await Promise.resolve()
  expect(screen.getByRole('heading', { name: 'Sesame cannot restore this backup.' })).toBeTruthy()
  expect(screen.getByText('Update Sesame, then choose this file again.')).toBeTruthy()
  expect(screen.queryByLabelText("This backup's master password or recovery kit")).toBeNull()
  expect(screen.queryByRole('button', { name: 'Restore backup' })).toBeNull()
  await vi.waitFor(() => expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true))
})

test('an unsupported backup gives one next action and offers no restore form', async () => {
  renderRestore('unsupported')
  await Promise.resolve()
  expect(screen.getByText('Keep this file and contact support.')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Restore backup' })).toBeNull()
  expect(screen.getByRole('button', { name: 'Close' })).toBeTruthy()
})

test('a failed open announces the backend message and keeps the form open', async () => {
  renderRestore('current', { errorMessage: 'That master password or recovery kit does not open this backup.' })
  await Promise.resolve()
  const alert = screen.getByRole('alert')
  expect(alert.textContent).toBe('That master password or recovery kit does not open this backup.')
  expect(alert.textContent).not.toMatch(/broken|damaged|corrupt/i)
  expect(screen.getByRole('button', { name: 'Restore backup' })).toBeTruthy()
})

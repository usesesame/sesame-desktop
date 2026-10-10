/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { RecoveryHealth } from '../types'
import BackupsView from './BackupsView.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function renderBackups(overrides: Record<string, unknown> = {}) {
  const props = {
    onExportBackup: vi.fn(),
    onConfirmPresence: vi.fn(),
    onBeginRestore: vi.fn(),
    onMakeBackup: vi.fn(),
    onOpenDrill: vi.fn(),
    ...overrides,
  }
  render(BackupsView, { props } as never)
  return props
}

function health(overrides: Partial<RecoveryHealth> = {}): RecoveryHealth {
  return { vaultId: 'fictional-vault', ...overrides }
}

test('an empty backup state offers every backup action and the copy reminder', async () => {
  const props = renderBackups()

  expect(screen.queryByText('Recovery health')).toBeNull()
  expect(screen.getByText('Before you rely on Sesame:')).toBeTruthy()

  await fireEvent.click(screen.getByRole('button', { name: 'Export backup' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Save snapshot' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Test a backup' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Choose backup' }))

  expect(props.onExportBackup).toHaveBeenCalledTimes(1)
  expect(props.onMakeBackup).toHaveBeenCalledTimes(1)
  expect(props.onOpenDrill).toHaveBeenCalledTimes(1)
  expect(props.onBeginRestore).toHaveBeenCalledTimes(1)
})

test('a current and verified backup reads as good', () => {
  renderBackups({
    currentRevision: 4,
    health: health({ lastExportedRevision: 4, lastVerifiedRevision: 4, lastExportedAt: '2026-10-01T10:00:00Z', lastVerifiedAt: '2026-10-01T10:00:00Z' }),
  })

  expect(screen.getByText('Your backup is up to date and verified.')).toBeTruthy()
})

test('a current backup without a drill asks for the drill', () => {
  renderBackups({
    currentRevision: 4,
    health: health({ lastExportedRevision: 4, lastVerifiedRevision: 3, lastExportedAt: '2026-10-01T10:00:00Z' }),
  })

  expect(screen.getByText('Your backup is current, but the recovery drill has not been completed.')).toBeTruthy()
})

test('a stale or missing backup record is called out', () => {
  renderBackups({ currentRevision: 4, health: health({ lastExportedRevision: 2, lastVerifiedRevision: 2 }) })

  expect(screen.getByText('No current backup has been recorded.')).toBeTruthy()
})

test('the export presence form blocks until the master password is entered and reports a failure', async () => {
  const props = renderBackups({
    exportPresenceRequired: true,
    errorMessage: 'That master password is not correct.',
  })

  const alert = screen.getByRole('alert')
  expect(alert.textContent).toBe('That master password is not correct.')

  const input = screen.getByLabelText('Master password') as HTMLInputElement
  expect(input.getAttribute('aria-invalid')).toBe('true')

  const confirm = screen.getByRole('button', { name: 'Confirm and export' }) as HTMLButtonElement
  expect(confirm.disabled).toBe(true)

  await fireEvent.input(input, { target: { value: 'fictional master password 01' } })
  expect(confirm.disabled).toBe(false)

  await fireEvent.submit(input.closest('form') as HTMLFormElement)
  expect(props.onConfirmPresence).toHaveBeenCalledTimes(1)
})

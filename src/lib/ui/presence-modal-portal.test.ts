/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import PasswordPresenceModal from './PasswordPresenceModal.svelte'

afterEach(cleanup)

beforeEach(() => {
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

test('cancel fires onCancel after the shell is portalled to body', async () => {
  const onCancel = vi.fn()
  render(PasswordPresenceModal, { presenceSecret: 'x', errorMessage: '', onCancel, onConfirm: vi.fn() })
  await Promise.resolve()
  const shell = document.querySelector('[data-modal-shell]')
  expect(shell).toBeTruthy()
  const appRoot = document.getElementById('app') as HTMLElement
  expect(shell?.parentElement).toBe(appRoot)
  const cancel = screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement
  expect(cancel.isConnected).toBe(true)
  await fireEvent.click(cancel)
  expect(onCancel).toHaveBeenCalledOnce()
})

test('unmounting removes the portalled shell from the document', async () => {
  const rendered = render(PasswordPresenceModal, { presenceSecret: 'x', errorMessage: '', onCancel: vi.fn(), onConfirm: vi.fn() })
  await Promise.resolve()
  expect(document.querySelector('[data-modal-shell]')).toBeTruthy()
  rendered.unmount()
  await Promise.resolve()
  expect(document.querySelector('[data-modal-shell]')).toBeNull()
})

test('a copy check names the copy and never offers to show the password', async () => {
  render(PasswordPresenceModal, { intent: 'copy', presenceSecret: 'x', errorMessage: '', onCancel: vi.fn(), onConfirm: vi.fn() })
  await Promise.resolve()
  expect(screen.getByRole('heading', { name: 'Copy this password' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Copy password' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Show password' })).toBeNull()
})

test('an enable check names the setting and never offers to show a password', async () => {
  render(PasswordPresenceModal, { intent: 'enable-icons', presenceSecret: 'x', errorMessage: '', onCancel: vi.fn(), onConfirm: vi.fn() })
  await Promise.resolve()
  expect(screen.getByRole('heading', { name: 'Turn on website icons' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Turn on' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Show password' })).toBeNull()
})

test('the new kit check offers to delete local backups and says the old kit still opens older ones', async () => {
  const rendered = render(PasswordPresenceModal, { intent: 'issue-kit', presenceSecret: 'x', errorMessage: '', onCancel: vi.fn(), onConfirm: vi.fn() })
  await Promise.resolve()
  expect(screen.getByRole('heading', { name: 'Get your new recovery kit' })).toBeTruthy()
  expect(screen.getByText(/Backups made before today still open with the old kit/)).toBeTruthy()
  const box = screen.getByRole('checkbox', { name: /delete the backup copies/i }) as HTMLInputElement
  expect(box.checked).toBe(false)
  rendered.unmount()
})

test('only the new kit check offers to delete local backups', async () => {
  render(PasswordPresenceModal, { intent: 'request-kit', presenceSecret: 'x', errorMessage: '', onCancel: vi.fn(), onConfirm: vi.fn() })
  await Promise.resolve()
  expect(screen.queryByRole('checkbox')).toBeNull()
})

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

/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import RollbackNoticeModal from './RollbackNoticeModal.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

test('nothing is shown without a notice', async () => {
  render(RollbackNoticeModal, { notice: null, onKeep: vi.fn(), onLock: vi.fn() })
  await Promise.resolve()
  expect(screen.queryByRole('dialog')).toBeNull()
})

test('the notice names both revisions and offers one primary action and a way to lock', async () => {
  const onKeep = vi.fn()
  const onLock = vi.fn()
  render(RollbackNoticeModal, { notice: { recordedRevision: 9, foundRevision: 4 }, onKeep, onLock })
  await Promise.resolve()
  const description = screen.getByText(/last opened revision/)
  expect(description.textContent).toContain('revision 4')
  expect(description.textContent).toContain('revision 9')
  expect(description.textContent).not.toMatch(/secure|safe|audited/i)
  screen.getByRole('button', { name: 'Keep using this vault' }).click()
  screen.getByRole('button', { name: 'Lock Sesame' }).click()
  expect(onKeep).toHaveBeenCalledTimes(1)
  expect(onLock).toHaveBeenCalledTimes(1)
})

test('a failure to keep the vault is announced and the buttons stay usable', async () => {
  render(RollbackNoticeModal, { notice: { recordedRevision: 9, foundRevision: 4 }, errorMessage: 'Sesame could not record the vault revision.', onKeep: vi.fn(), onLock: vi.fn() })
  await Promise.resolve()
  expect(screen.getByRole('alert').textContent).toBe('Sesame could not record the vault revision.')
  expect((screen.getByRole('button', { name: 'Keep using this vault' }) as HTMLButtonElement).disabled).toBe(false)
})

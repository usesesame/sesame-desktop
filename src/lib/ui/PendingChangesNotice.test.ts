/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { PendingChangeView } from '../types'
import PendingChangesNotice from './PendingChangesNotice.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function view(partial: Partial<PendingChangeView>): PendingChangeView {
  return {
    id: 'change-1',
    itemId: 'login-a',
    kind: 'change',
    host: 'example.com',
    title: 'Northwind',
    username: 'casey@example.com',
    createdAt: 1,
    fill: 'unknown',
    accepted: false,
    canGoBack: true,
    superseded: false,
    daysLeft: 30,
    urgent: false,
    ...partial,
  }
}

function handlers() {
  return { onKeep: vi.fn(), onGoBack: vi.fn(), onDiscard: vi.fn(), onCopy: vi.fn(), onEdit: vi.fn(), onOpenHistory: vi.fn() }
}

test('an older change in a chain offers its history and nothing that rewrites the password', async () => {
  const actions = handlers()
  const change = view({ canGoBack: false, superseded: true, fill: 'notFilled' })
  render(PendingChangesNotice, { changes: [change], ...actions })

  expect(screen.getByText('A newer password was saved for Northwind since this one. Open its history to see each version.')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /go back/i })).toBeNull()
  expect(screen.queryByRole('button', { name: /copy password/i })).toBeNull()
  await fireEvent.click(screen.getByRole('button', { name: 'Open history' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))

  expect(actions.onOpenHistory).toHaveBeenCalledWith(change)
  expect(actions.onKeep).toHaveBeenCalledWith(change)
  expect(actions.onGoBack).not.toHaveBeenCalled()
})

test('the newest change still offers to go back', () => {
  render(PendingChangesNotice, { changes: [view({ fill: 'notFilled' })], ...handlers() })

  expect(screen.getByRole('button', { name: 'Go back to old password' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Open history' })).toBeNull()
})

test('a change whose login was edited since offers its history instead of a way back', () => {
  render(PendingChangesNotice, { changes: [view({ canGoBack: false, superseded: false, daysLeft: 20 })], ...handlers() })

  expect(screen.getByText('Northwind changed after Sesame saved this password. Open its history to see each version.')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Open history' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: /go back/i })).toBeNull()
})

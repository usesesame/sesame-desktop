/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { MergeComparison } from '../types'
import ConfirmMergeModal from './ConfirmMergeModal.svelte'

const vaultApi = vi.hoisted(() => ({
  grantPresence: vi.fn(),
  revealLoginSecret: vi.fn(),
}))

vi.mock('../vault', () => ({
  PRESENCE_REQUIRED: 'presenceRequired',
  ...vaultApi,
}))

const passwords: Record<string, string> = {
  'login-a': 'fictional-alpha-password',
  'login-b': 'fictional-bravo-password',
}

const entries = [
  { id: 'login-a', title: 'Alpha', initials: 'A', site: 'northwind.example', username: 'fictional-user', reason: 'Same website and username' },
  { id: 'login-b', title: 'Bravo', initials: 'B', site: 'northwind.example', username: 'fictional-user', reason: 'Same website and username' },
]

const comparison: MergeComparison = {
  entries: entries.map((entry) => ({ id: entry.id, title: entry.title, site: entry.site, username: entry.username, updatedAt: 1, revision: 1 })),
  fields: [
    { field: 'email', label: 'Email', secret: false, differs: true, options: [{ entryId: 'login-a', present: true, value: 'alpha@example.test' }, { entryId: 'login-b', present: false }] },
    { field: 'password', label: 'Password', secret: true, differs: true, options: [{ entryId: 'login-a', present: true }, { entryId: 'login-b', present: true }] },
    { field: 'totp', label: '2FA secret', secret: true, differs: true, options: [{ entryId: 'login-a', present: true }, { entryId: 'login-b', present: false }] },
    { field: 'notes', label: 'Notes', secret: true, differs: true, options: [{ entryId: 'login-a', present: true }, { entryId: 'login-b', present: true }] },
  ],
}

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
  vaultApi.grantPresence.mockReset()
  vaultApi.revealLoginSecret.mockReset()
  vaultApi.revealLoginSecret.mockImplementation(async (id: string) => passwords[id])
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
  vi.useRealTimers()
})

function renderMerge() {
  return render(ConfirmMergeModal, {
    mergeCandidate: { group: { id: 'group', label: 'northwind.example', site: 'northwind.example', entries }, entries },
    mergeKeepId: 'login-a',
    mergeComparison: comparison,
    mergeChoices: {},
    cleanupWorking: false,
    onCancel: vi.fn(),
    onConfirm: vi.fn(),
  })
}

test('secret fields show only whether a value exists and plain fields show their value', async () => {
  renderMerge()
  await Promise.resolve()

  expect(screen.getByText('alpha@example.test')).toBeTruthy()
  expect(screen.getAllByText('Hidden').length).toBe(5)
  expect(screen.getAllByText('Empty').length).toBe(2)
  expect(document.body.textContent).not.toContain('fictional-alpha-password')
  expect(vaultApi.revealLoginSecret).not.toHaveBeenCalled()
})

test('only the password offers a show button', async () => {
  renderMerge()
  await Promise.resolve()

  expect(screen.getAllByRole('button', { name: /^Show the password of/ }).length).toBe(2)
  expect(screen.queryByRole('button', { name: /2FA|notes/i })).toBeNull()
})

test('showing one password reads it for that login only and a second show replaces it', async () => {
  renderMerge()
  await Promise.resolve()

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Alpha' }))
  await waitFor(() => expect(screen.getByText('fictional-alpha-password')).toBeTruthy())
  expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(1)
  expect(vaultApi.revealLoginSecret).toHaveBeenCalledWith('login-a')

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Bravo' }))
  await waitFor(() => expect(screen.getByText('fictional-bravo-password')).toBeTruthy())
  expect(screen.queryByText('fictional-alpha-password')).toBeNull()
})

test('hide removes the shown password', async () => {
  renderMerge()
  await Promise.resolve()

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Alpha' }))
  await waitFor(() => expect(screen.getByText('fictional-alpha-password')).toBeTruthy())
  await fireEvent.click(screen.getByRole('button', { name: 'Hide the password of Alpha' }))

  expect(screen.queryByText('fictional-alpha-password')).toBeNull()
})

test('a shown password hides itself after thirty seconds', async () => {
  renderMerge()
  await Promise.resolve()
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Alpha' }))
  await vi.waitFor(() => expect(screen.getByText('fictional-alpha-password')).toBeTruthy())
  await vi.advanceTimersByTimeAsync(30_000)

  expect(screen.queryByText('fictional-alpha-password')).toBeNull()
})

test('without a recent presence check the master password is asked for, then the password is shown', async () => {
  vaultApi.revealLoginSecret.mockRejectedValueOnce(new Error('presenceRequired'))
  vaultApi.grantPresence.mockResolvedValue(undefined)
  renderMerge()
  await Promise.resolve()

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Alpha' }))
  const field = (await screen.findByLabelText('Master password')) as HTMLInputElement
  expect(screen.queryByText('fictional-alpha-password')).toBeNull()

  await fireEvent.input(field, { target: { value: 'fictional master password' } })
  await fireEvent.click(screen.getByRole('button', { name: 'Confirm and show' }))

  await waitFor(() => expect(screen.getByText('fictional-alpha-password')).toBeTruthy())
  expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password')
  expect(screen.queryByLabelText('Master password')).toBeNull()
})

test('a wrong master password keeps the password hidden and clears the field', async () => {
  vaultApi.revealLoginSecret.mockRejectedValueOnce(new Error('presenceRequired'))
  vaultApi.grantPresence.mockRejectedValue(new Error('That master password does not open this vault.'))
  renderMerge()
  await Promise.resolve()

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Alpha' }))
  const field = (await screen.findByLabelText('Master password')) as HTMLInputElement
  await fireEvent.input(field, { target: { value: 'fictional wrong password' } })
  await fireEvent.click(screen.getByRole('button', { name: 'Confirm and show' }))

  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('does not open this vault'))
  expect(field.value).toBe('')
  expect(screen.queryByText('fictional-alpha-password')).toBeNull()
  expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(1)
})

test('cancelling the master password check leaves every password hidden', async () => {
  vaultApi.revealLoginSecret.mockRejectedValueOnce(new Error('presenceRequired'))
  renderMerge()
  await Promise.resolve()

  await fireEvent.click(screen.getByRole('button', { name: 'Show the password of Alpha' }))
  await screen.findByLabelText('Master password')
  await fireEvent.click(screen.getAllByRole('button', { name: 'Cancel' })[0])

  expect(screen.queryByLabelText('Master password')).toBeNull()
  expect(screen.queryByText('fictional-alpha-password')).toBeNull()
})

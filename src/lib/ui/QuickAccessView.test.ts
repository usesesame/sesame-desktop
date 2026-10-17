/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { QuickAccessItem } from '../types'

const vaultApi = vi.hoisted(() => ({
  copyQuickAccessField: vi.fn(),
  getQuickAccessStatus: vi.fn(),
  openQuickAccessItem: vi.fn(),
  searchQuickAccessItems: vi.fn(),
}))

vi.mock('../vault', () => ({
  ...vaultApi,
  PRESENCE_REQUIRED: 'presenceRequired',
  previewMode: true,
}))

import QuickAccessView from './QuickAccessView.svelte'

const login: QuickAccessItem = {
  id: 'fictional-login',
  kind: 'login',
  title: 'Northwind',
  subtitle: 'northwind.example',
  initials: 'N',
  actions: [
    { field: 'password', label: 'Copy password', guarded: true },
    { field: 'username', label: 'Copy username', guarded: false },
  ],
}

beforeEach(() => {
  vaultApi.getQuickAccessStatus.mockResolvedValue({ exists: true, unlocked: true })
  vaultApi.searchQuickAccessItems.mockResolvedValue([login])
  vaultApi.openQuickAccessItem.mockResolvedValue(undefined)
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
  document.body.replaceChildren()
})

test('a password copy that needs the master password points to the main window and copies nothing', async () => {
  vaultApi.copyQuickAccessField.mockRejectedValue(new Error('presenceRequired'))
  render(QuickAccessView)

  await fireEvent.click(await screen.findByRole('button', { name: /Copy password/ }))

  expect(await screen.findByText(/Confirm your master password in Sesame to copy from Northwind/)).toBeTruthy()

  await fireEvent.click(screen.getByRole('button', { name: 'Open Sesame' }))
  expect(vaultApi.openQuickAccessItem).toHaveBeenCalledWith('fictional-login')
})

test('a password copy runs in the host and the window never holds the value', async () => {
  vaultApi.copyQuickAccessField.mockResolvedValue(undefined)
  render(QuickAccessView)

  await fireEvent.click(await screen.findByRole('button', { name: /Copy password/ }))

  await waitFor(() => expect(vaultApi.copyQuickAccessField).toHaveBeenCalledWith('fictional-login', 'password'))
  expect(await screen.findByText(/password copied/i)).toBeTruthy()
  expect(screen.queryByText(/Confirm your master password/)).toBeNull()
})

test('another host error does not claim the master password is missing', async () => {
  vaultApi.copyQuickAccessField.mockRejectedValue(new Error('Nothing is saved in that field for this item.'))
  render(QuickAccessView)

  await fireEvent.click(await screen.findByRole('button', { name: /Copy password/ }))

  await waitFor(() => expect(vaultApi.copyQuickAccessField).toHaveBeenCalled())
  expect(screen.queryByText(/Confirm your master password/)).toBeNull()
})

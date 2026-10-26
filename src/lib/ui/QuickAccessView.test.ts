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
  Element.prototype.scrollIntoView = vi.fn()
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

const second: QuickAccessItem = { ...login, id: 'fictional-second', title: 'Contoso', subtitle: 'contoso.example', initials: 'C' }

function rows() {
  return [...document.querySelectorAll('.quick-access-result-row')] as HTMLElement[]
}

test('a pointer that only rests over the list does not take the selection from the keyboard', async () => {
  vaultApi.searchQuickAccessItems.mockResolvedValue([login, second])
  render(QuickAccessView)
  await screen.findByText('Contoso')

  await fireEvent.keyDown(window, { key: 'ArrowDown' })
  expect(rows()[1].classList.contains('active')).toBe(true)

  await fireEvent.mouseEnter(rows()[0].querySelector('button') as HTMLElement)
  expect(rows()[1].classList.contains('active')).toBe(true)
})

test('moving the pointer over a result selects it', async () => {
  vaultApi.searchQuickAccessItems.mockResolvedValue([login, second])
  render(QuickAccessView)
  await screen.findByText('Contoso')

  await fireEvent.mouseMove(rows()[1].querySelector('button') as HTMLElement)
  expect(rows()[1].classList.contains('active')).toBe(true)
})

test('the arrow keys keep the selected result in view', async () => {
  const scrolled = vi.fn()
  Element.prototype.scrollIntoView = scrolled
  vaultApi.searchQuickAccessItems.mockResolvedValue([login, second])
  render(QuickAccessView)
  await screen.findByText('Contoso')

  await fireEvent.keyDown(window, { key: 'ArrowDown' })
  await waitFor(() => expect(scrolled).toHaveBeenCalledWith({ block: 'nearest' }))
})

test('a copy that fails for any other reason says so instead of going quiet', async () => {
  vaultApi.copyQuickAccessField.mockRejectedValue(new Error('Nothing is saved in that field for this item.'))
  render(QuickAccessView)

  await fireEvent.click(await screen.findByRole('button', { name: /Copy password/ }))

  expect((await screen.findByRole('alert')).textContent).toContain('Sesame could not copy that')
})

test('an item that cannot be opened says so', async () => {
  vaultApi.copyQuickAccessField.mockRejectedValue(new Error('presenceRequired'))
  vaultApi.openQuickAccessItem.mockRejectedValue(new Error('gone'))
  render(QuickAccessView)

  await fireEvent.click(await screen.findByRole('button', { name: /Copy password/ }))
  await fireEvent.click(await screen.findByRole('button', { name: 'Open Sesame' }))

  expect((await screen.findByRole('alert')).textContent).toContain('Sesame could not open that')
})

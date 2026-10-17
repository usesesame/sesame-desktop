/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import AppChrome from './AppChrome.svelte'
import Sidebar from './Sidebar.svelte'

vi.mock('../vault', () => ({ controlWindow: vi.fn() }))

afterEach(() => cleanup())

test('the window bar says Local vault when the vault is not synced', () => {
  render(AppChrome, {})
  expect(screen.getByText('Local vault')).toBeTruthy()
  expect(document.querySelector('.chrome-sync-dot')).toBeNull()
})

test('the window bar names the synced vault and its status, with a dot that carries the state', () => {
  render(AppChrome, { syncStatusLabel: 'Synced vault · Syncing…', syncTone: 'busy' })
  const status = screen.getByRole('status')
  expect(status.textContent).toContain('Synced vault · Syncing…')
  expect(status.querySelector('.chrome-sync-dot.busy')).toBeTruthy()
  expect(screen.queryByText('Local vault')).toBeNull()
})

test('a warning status gets the warning dot', () => {
  render(AppChrome, { syncStatusLabel: 'Synced vault · Offline, will retry', syncTone: 'warn' })
  expect(document.querySelector('.chrome-sync-dot.warn')).toBeTruthy()
})

test('the sidebar footer follows the same vault label', () => {
  const props = { navigation: [], activeView: 'vault' as const, autoLockMinutes: 5, onNavigate: vi.fn(), onLock: vi.fn() }
  const { unmount } = render(Sidebar, { ...props })
  expect(screen.getByText('Local vault')).toBeTruthy()
  unmount()
  render(Sidebar, { ...props, vaultLabel: 'Synced vault' })
  expect(screen.getByText('Synced vault')).toBeTruthy()
})

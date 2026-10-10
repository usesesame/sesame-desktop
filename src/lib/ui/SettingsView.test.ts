/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import type { PlatformCapabilities } from '../types'
import SettingsView from './SettingsView.svelte'

vi.mock('../vault', () => ({ getPlatformCapabilities: vi.fn() }))

const host: PlatformCapabilities = { os: 'linux', pinUnlock: true, biometricUnlock: false, autoType: false, browserIntegration: false, sessionAutoLock: false, quickAccessShortcut: false, accountLinking: false, desktopUpdates: false, windowControls: false }

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  document.body.replaceChildren()
})

function renderSettings(desktopUpdates: boolean) {
  platformCapabilities.set({ ...host, desktopUpdates })
  const onCheckForUpdate = vi.fn()
  render(SettingsView, { props: { tab: 'general', onCheckForUpdate, onInstallUpdate: vi.fn() } } as never)
  return { onCheckForUpdate }
}

test('a system without desktop updates offers no update button and says how to update', () => {
  renderSettings(false)
  expect(screen.queryByRole('button', { name: 'Check now' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Install update' })).toBeNull()
  expect(screen.getByText(/Sesame does not update itself on this system/)).toBeTruthy()
})

test('a system with desktop updates offers the check button', () => {
  renderSettings(true)
  expect(screen.getByRole('button', { name: 'Check now' })).toBeTruthy()
  expect(screen.queryByText(/does not update itself/)).toBeNull()
})

/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import type { DesktopUpdateProgress, DesktopUpdateStatus, PlatformCapabilities } from '../types'
import SettingsView from './SettingsView.svelte'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.stubGlobal('ResizeObserver', ResizeObserverStub)

const linux = (overrides: Partial<PlatformCapabilities> = {}): PlatformCapabilities => ({
  os: 'linux',
  pinUnlock: false,
  biometricUnlock: false,
  autoType: false,
  browserIntegration: false,
  sessionAutoLock: false,
  quickAccessShortcut: false,
  accountLinking: false,
  desktopUpdates: false,
  windowControls: false,
  ...overrides,
})

beforeEach(() => {
  platformCapabilities.set(linux())
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function renderSettings(overrides: Record<string, unknown> = {}) {
  const props = {
    onSetClipboardClearSeconds: vi.fn(),
    onTogglePin: vi.fn(),
    onToggleHello: vi.fn(),
    onChangeMasterPassword: vi.fn(),
    onToggleTray: vi.fn(),
    onToggleAutostart: vi.fn(),
    onUpdateQuickAccessShortcut: vi.fn(),
    onSetTheme: vi.fn(),
    onSetSiteIconsEnabled: vi.fn(),
    onConfirmSiteIconsPresence: vi.fn(),
    onCancelSiteIconsPresence: vi.fn(),
    onClearWebsiteIconCache: vi.fn(),
    onSetAutoLockMinutes: vi.fn(),
    onManageData: vi.fn(),
    onExportDiagnostics: vi.fn(),
    onClearDiagnostics: vi.fn(),
    onLinkService: vi.fn(),
    onDisconnectService: vi.fn(),
    onRefreshService: vi.fn(),
    onCheckForUpdate: vi.fn(),
    onInstallUpdate: vi.fn(),
    onRefreshBrowserIntegration: vi.fn(),
    onRepairBrowserIntegration: vi.fn(),
    onOpenWebsite: vi.fn(),
    ...overrides,
  }
  render(SettingsView, { props } as never)
  return props
}

test('a platform without self-updates shows no update control and says how updates arrive', () => {
  renderSettings()

  expect(screen.getByText(/Sesame does not update itself on this system/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Check now' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Install update' })).toBeNull()
})

test('a platform with self-updates can check the signed feed', async () => {
  platformCapabilities.set(linux({ desktopUpdates: true }))
  const props = renderSettings({ desktopUpdate: { available: false } satisfies DesktopUpdateStatus })

  const check = screen.getByRole('button', { name: 'Check now' })
  expect(screen.queryByRole('button', { name: 'Install update' })).toBeNull()

  await fireEvent.click(check)
  expect(props.onCheckForUpdate).toHaveBeenCalledTimes(1)
})

test('an available update names the version and installs on request', async () => {
  platformCapabilities.set(linux({ desktopUpdates: true }))
  const props = renderSettings({ desktopUpdate: { available: true, version: '0.4.0' } })

  expect(screen.getByText(/Version 0\.4\.0 is ready to install/)).toBeTruthy()

  await fireEvent.click(screen.getByRole('button', { name: 'Install update' }))
  expect(props.onInstallUpdate).toHaveBeenCalledTimes(1)
})

test('an update in progress blocks a second request and reports the download', () => {
  platformCapabilities.set(linux({ desktopUpdates: true }))
  const progress: DesktopUpdateProgress = { downloadedBytes: 50, totalBytes: 100 }
  renderSettings({ desktopUpdate: { available: false }, updateWorking: true, updateProgress: progress })

  expect(screen.getByText(/Downloading verified update, 50% complete/)).toBeTruthy()
  const checking = screen.getByRole('button', { name: 'Checking…' }) as HTMLButtonElement
  expect(checking.disabled).toBe(true)
})

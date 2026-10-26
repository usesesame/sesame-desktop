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
  systemIdle: false,
  screenLockMonitoring: false,
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

test('a Linux desktop that reports no screen lock source says the vault will not follow the screen lock', () => {
  renderSettings({ tab: 'security' })

  expect(screen.getByText(/Sesame cannot tell when this desktop locks its screen/)).toBeTruthy()
})

test('a Linux desktop that reports a screen lock source shows no screen lock warning', () => {
  platformCapabilities.set(linux({ screenLockMonitoring: true }))
  renderSettings({ tab: 'security' })

  expect(screen.queryByText(/Sesame cannot tell when this desktop locks its screen/)).toBeNull()
})

test('Windows shows no screen lock warning', () => {
  platformCapabilities.set(linux({ os: 'windows', screenLockMonitoring: true }))
  renderSettings({ tab: 'security' })

  expect(screen.queryByText(/Sesame cannot tell when this desktop locks its screen/)).toBeNull()
})

test('the Connections tab shows the server connection group once', () => {
  renderSettings({ tab: 'connections' })

  expect(screen.getAllByRole('heading', { name: 'Connect to your own server' })).toHaveLength(1)
  expect(screen.getAllByText('Pairing link or server address')).toHaveLength(1)
})

const registered = { supported: true, hostAvailable: true, manifestReady: true, chromeRegistered: true, edgeRegistered: true, firefoxRegistered: true, ready: true, servedElsewhere: false, code: 'ready' as const }

test('a working browser connection hides the Browser group', () => {
  renderSettings({ tab: 'connections', browserIntegration: registered })

  expect(screen.queryByRole('heading', { name: 'Browser' })).toBeNull()
})

test('a browser connection that another Sesame holds keeps the Browser group visible', () => {
  renderSettings({ tab: 'connections', browserIntegration: { ...registered, servedElsewhere: true } })

  expect(screen.getByRole('heading', { name: 'Browser' })).toBeTruthy()
  expect(screen.getByText('Used by another Sesame')).toBeTruthy()
})

test('Sync has its own group on the Connections tab, apart from the account', () => {
  renderSettings({ tab: 'connections' })

  expect(screen.getByRole('heading', { name: 'Sesame Sync' })).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Sesame account' })).toBeTruthy()
})

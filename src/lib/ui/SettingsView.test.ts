/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, within } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import type { DesktopUpdateProgress, DesktopUpdateStatus, PlatformCapabilities } from '../types'
import { SETTINGS_TABS } from '../settings-tabs'
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

const registered = { supported: true, hostAvailable: true, manifestReady: true, chromeRegistered: true, edgeRegistered: true, firefoxRegistered: true, ready: true, servedElsewhere: false, code: 'ready' as const }

function groupHeadings(): string[] {
  return screen.getAllByRole('heading', { level: 3 }).map((heading) => heading.textContent ?? '')
}

test.each([
  ['general', ['Appearance', 'This app', 'Shortcuts']],
  ['security', ['This device', 'Your vault key']],
  ['browser', ['Extension', 'Saving']],
  ['sync', ['Sesame account', 'Sesame Sync', 'Your own server']],
  ['extras', ['Email aliases']],
  ['data', ['Your vault', 'Diagnostics']],
])('the %s tab shows its own groups and no other tab\'s', (tab, headings) => {
  renderSettings({ tab })

  expect(groupHeadings()).toEqual(headings)
})

test('every tab in the list renders a panel with at least one group', () => {
  for (const item of SETTINGS_TABS) {
    renderSettings({ tab: item.id })
    const panel = screen.getByRole('tabpanel')
    expect(panel.getAttribute('aria-labelledby')).toBe(`settings-tab-${item.id}`)
    expect(within(panel).getAllByRole('heading', { level: 3 }).length).toBeGreaterThan(0)
    cleanup()
  }
})

test('each setting sits on its own tab', () => {
  renderSettings({ tab: 'general' })
  expect(screen.getByText('Theme')).toBeTruthy()
  expect(screen.getByText('Keyboard shortcuts')).toBeTruthy()
  expect(screen.queryByText('Sites Sesame never saves')).toBeNull()
  expect(screen.queryByText('Browser autofill setup')).toBeNull()
  cleanup()

  renderSettings({ tab: 'browser' })
  expect(screen.getByText('Browser autofill setup')).toBeTruthy()
  expect(screen.getByText('Sites Sesame never saves')).toBeTruthy()
  expect(screen.queryByRole('heading', { name: 'Sesame Sync' })).toBeNull()
  expect(screen.queryByText('Pairing link or server address')).toBeNull()
  cleanup()

  renderSettings({ tab: 'sync' })
  expect(screen.getAllByText('Pairing link or server address')).toHaveLength(1)
  expect(screen.queryByText('Sites Sesame never saves')).toBeNull()
  expect(screen.queryByText('Browser autofill setup')).toBeNull()
  expect(screen.queryByText('Theme')).toBeNull()
  expect(screen.queryByRole('switch', { name: 'Email aliases' })).toBeNull()
  cleanup()

  renderSettings({ tab: 'extras' })
  expect(screen.getAllByRole('switch', { name: 'Email aliases' })).toHaveLength(1)
  expect(screen.queryByText('Sites Sesame never saves')).toBeNull()
  expect(screen.queryByText('Pairing link or server address')).toBeNull()
})

test('the quick access shortcut joins the Shortcuts group where the platform has one', () => {
  platformCapabilities.set(linux({ quickAccessShortcut: true }))
  renderSettings({ tab: 'general' })

  const shortcuts = screen.getByRole('heading', { name: 'Shortcuts' }).closest('section') as HTMLElement
  expect(within(shortcuts).getByText('Quick access shortcut')).toBeTruthy()
  expect(within(shortcuts).getByText('Keyboard shortcuts')).toBeTruthy()
})

test('the Sync tab shows the server connection group once', () => {
  renderSettings({ tab: 'sync' })

  expect(screen.getAllByRole('heading', { name: 'Your own server' })).toHaveLength(1)
  expect(screen.getAllByText('Pairing link or server address')).toHaveLength(1)
})

test('a paired server of your own hides the Sesame account group', () => {
  renderSettings({ tab: 'sync', serviceConnection: { state: 'connected', connected: true, online: true, syncAvailable: true, browserHelperAvailable: false, serverAddress: 'https://sync.example.test', serverName: 'Example server' } })

  expect(screen.queryByRole('heading', { name: 'Sesame account' })).toBeNull()
  expect(screen.getByRole('heading', { name: 'Your own server' })).toBeTruthy()
})

test('a working browser connection hides the Extension group and keeps Saving', () => {
  renderSettings({ tab: 'browser', browserIntegration: registered })

  expect(groupHeadings()).toEqual(['Saving'])
})

test('a browser connection that another Sesame holds keeps the Extension group visible', () => {
  renderSettings({ tab: 'browser', browserIntegration: { ...registered, servedElsewhere: true } })

  expect(screen.getByRole('heading', { name: 'Extension' })).toBeTruthy()
  expect(screen.getByText('Used by another Sesame')).toBeTruthy()
})

test('the Sync tab opened by name is selected and labels its panel', () => {
  renderSettings({ tab: 'sync' })

  const syncTab = screen.getByRole('tab', { name: 'Sync' })
  expect(syncTab.getAttribute('aria-selected')).toBe('true')
  expect(syncTab.tabIndex).toBe(0)
  expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe(syncTab.id)
  expect(screen.getByRole('heading', { name: 'Sesame Sync' })).toBeTruthy()
})

test('arrow keys, Home and End move between tabs and focus the new tab', async () => {
  renderSettings()
  const names = SETTINGS_TABS.map((item) => item.label)
  const selected = () => screen.getAllByRole('tab').filter((tab) => tab.getAttribute('aria-selected') === 'true').map((tab) => tab.textContent?.trim())

  expect(screen.getAllByRole('tab').map((tab) => tab.textContent?.trim())).toEqual(names)
  expect(selected()).toEqual(['General'])

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'General' }), { key: 'ArrowRight' })
  expect(selected()).toEqual(['Security'])
  expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Security' }))
  expect(screen.getByRole('heading', { name: 'This device' })).toBeTruthy()

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Security' }), { key: 'ArrowRight' })
  expect(selected()).toEqual(['Browser'])
  expect(screen.getByRole('heading', { name: 'Saving' })).toBeTruthy()

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Browser' }), { key: 'ArrowLeft' })
  expect(selected()).toEqual(['Security'])

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Security' }), { key: 'End' })
  expect(selected()).toEqual([names.at(-1)])
  expect(document.activeElement).toBe(screen.getByRole('tab', { name: names.at(-1) }))

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Data' }), { key: 'ArrowLeft' })
  expect(selected()).toEqual(['Extras'])
  expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Extras' }))
  expect(screen.getByRole('heading', { name: 'Email aliases' })).toBeTruthy()

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Extras' }), { key: 'ArrowLeft' })
  expect(selected()).toEqual(['Sync'])

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Sync' }), { key: 'ArrowRight' })
  expect(selected()).toEqual(['Extras'])

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'Extras' }), { key: 'End' })
  expect(selected()).toEqual([names.at(-1)])

  await fireEvent.keyDown(screen.getByRole('tab', { name: names.at(-1) }), { key: 'ArrowRight' })
  expect(selected()).toEqual(['General'])

  await fireEvent.keyDown(screen.getByRole('tab', { name: 'General' }), { key: 'ArrowLeft' })
  expect(selected()).toEqual([names.at(-1)])

  await fireEvent.keyDown(screen.getByRole('tab', { name: names.at(-1) }), { key: 'Home' })
  expect(selected()).toEqual(['General'])
  expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'General' }))
})

test('clicking a tab shows its panel', async () => {
  renderSettings()

  await fireEvent.click(screen.getByRole('tab', { name: 'Sync' }))

  expect(screen.getByRole('tab', { name: 'Sync' }).getAttribute('aria-selected')).toBe('true')
  expect(screen.getByRole('heading', { name: 'Sesame Sync' })).toBeTruthy()
  expect(screen.queryByRole('heading', { name: 'Appearance' })).toBeNull()
})

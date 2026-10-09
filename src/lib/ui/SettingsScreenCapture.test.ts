/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import SettingsView from './SettingsView.svelte'

vi.mock('../vault', () => ({ getPlatformCapabilities: vi.fn() }))

const hostCapabilities = { pinUnlock: false, biometricUnlock: false, autoType: false, browserIntegration: false, sessionAutoLock: false, quickAccessShortcut: false, accountLinking: false, desktopUpdates: false, windowControls: false }

beforeEach(() => {
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  platformCapabilities.set({ os: 'windows', ...hostCapabilities })
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  document.body.replaceChildren()
})

async function renderSecurityTab(props: Record<string, unknown> = {}) {
  const rendered = render(SettingsView, {
    props: {
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
      onSetClipboardClearSeconds: vi.fn(),
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
      ...props,
    },
  } as never)
  await fireEvent.click(screen.getByRole('tab', { name: /Security/ }))
  return rendered
}

test('the screen capture switch is off by default and asks to change when pressed', async () => {
  const onToggleScreenCapture = vi.fn()
  await renderSecurityTab({ onToggleScreenCapture })

  const toggle = screen.getByRole('switch', { name: 'Allow screen capture' })
  expect(toggle.getAttribute('aria-checked')).toBe('false')
  await fireEvent.click(toggle)
  expect(onToggleScreenCapture).toHaveBeenCalledTimes(1)
})

test('the screen capture switch shows the allowed state and is disabled while a change runs', async () => {
  await renderSecurityTab({ screenCaptureAllowed: true, screenCaptureWorking: true })

  const toggle = screen.getByRole('switch', { name: 'Allow screen capture' }) as HTMLButtonElement
  expect(toggle.getAttribute('aria-checked')).toBe('true')
  expect(toggle.disabled).toBe(true)
})

test('the screen capture switch is absent where Sesame cannot hide its windows', async () => {
  platformCapabilities.set({ os: 'linux', ...hostCapabilities })
  await renderSecurityTab()

  expect(screen.queryByRole('switch', { name: 'Allow screen capture' })).toBeNull()
})

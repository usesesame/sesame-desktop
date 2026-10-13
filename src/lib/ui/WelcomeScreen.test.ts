/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import type { PlatformCapabilities } from '../types'
import WelcomeScreen from './WelcomeScreen.svelte'

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

function renderWelcome(overrides: Record<string, unknown> = {}) {
  const onStart = vi.fn()
  const onRestoreBackup = vi.fn()
  render(WelcomeScreen, { props: { onStart, onRestoreBackup, ...overrides } } as never)
  return { onStart, onRestoreBackup }
}

test('start setup and restore from a backup each call their handler', async () => {
  const { onStart, onRestoreBackup } = renderWelcome()

  await fireEvent.click(screen.getByRole('button', { name: 'Start setup' }))
  expect(onStart).toHaveBeenCalledTimes(1)
  expect(onRestoreBackup).not.toHaveBeenCalled()

  await fireEvent.click(screen.getByRole('button', { name: 'Restore from a backup' }))
  expect(onRestoreBackup).toHaveBeenCalledTimes(1)
})

test('a failed restore is announced instead of leaving the screen silent', () => {
  renderWelcome({ errorMessage: 'That backup could not be read. Keep the file and try again.' })

  expect(screen.getByRole('alert').textContent).toBe('That backup could not be read. Keep the file and try again.')
})

test('the heading receives focus on arrival', async () => {
  renderWelcome()
  await vi.waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Welcome to Sesame' })))
})

test('the PIN step appears only when the platform offers an everyday unlock', () => {
  renderWelcome()
  expect(screen.queryByText(/Pick a PIN/)).toBeNull()

  cleanup()
  platformCapabilities.set(linux({ pinUnlock: true }))
  renderWelcome()
  expect(screen.getByText('Pick a PIN for everyday unlock.')).toBeTruthy()
})

test('Windows Hello is named when the platform has it', () => {
  platformCapabilities.set(linux({ pinUnlock: true, biometricUnlock: true }))
  renderWelcome()
  expect(screen.getByText('Pick a PIN or Windows Hello for everyday unlock.')).toBeTruthy()
})

/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import type { VaultStatus } from '../types'
import UnlockScreen from './UnlockScreen.svelte'

vi.mock('../vault', () => ({ getPlatformCapabilities: vi.fn() }))

const status: VaultStatus = {
  exists: true,
  unlocked: false,
  preview: false,
  pinUnlockAvailable: true,
  helloUnlockAvailable: false,
  onboardingRequired: false,
  revision: 1,
}

beforeEach(() => {
  platformCapabilities.set({ os: 'linux', pinUnlock: true, biometricUnlock: false, autoType: false, browserIntegration: false, sessionAutoLock: false, systemIdle: false, screenLockMonitoring: false, quickAccessShortcut: false, accountLinking: false, desktopUpdates: false, windowControls: false })
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function renderPinUnlock() {
  const onUnlockWithPin = vi.fn()
  const rendered = render(UnlockScreen, { props: { status, onUnlockWithPin, onUnlockWithHello: vi.fn(), onSubmitMasterPassword: vi.fn() } } as never)
  const field = rendered.container.querySelector('.pin-entry') as HTMLInputElement
  const submit = screen.getByRole('button', { name: 'Unlock vault' }) as HTMLButtonElement
  const dots = () => rendered.container.querySelectorAll('.pin-dot').length
  return { rendered, field, submit, dots, onUnlockWithPin }
}

test('six digits do not unlock on their own, and the button submits them', async () => {
  const { field, submit, onUnlockWithPin } = renderPinUnlock()
  expect(submit.disabled).toBe(true)

  await fireEvent.input(field, { target: { value: '47291' } })
  expect(submit.disabled).toBe(true)

  await fireEvent.input(field, { target: { value: '472913' } })
  expect(onUnlockWithPin).not.toHaveBeenCalled()
  expect(submit.disabled).toBe(false)

  await fireEvent.click(submit)
  expect(onUnlockWithPin).toHaveBeenCalledTimes(1)
})

test('the field shows six dots and adds one per digit up to twelve', async () => {
  const { field, dots, rendered, onUnlockWithPin } = renderPinUnlock()
  const filled = () => rendered.container.querySelectorAll('.pin-dot.filled').length
  expect(dots()).toBe(6)
  expect(filled()).toBe(0)

  await fireEvent.input(field, { target: { value: '472' } })
  expect(dots()).toBe(6)
  expect(filled()).toBe(3)

  await fireEvent.input(field, { target: { value: '4729138' } })
  expect(dots()).toBe(7)
  expect(filled()).toBe(7)

  await fireEvent.input(field, { target: { value: '47 2913850261999' } })
  expect(field.value).toBe('472913850261')
  expect(dots()).toBe(12)

  await fireEvent.submit(field.form as HTMLFormElement)
  expect(onUnlockWithPin).toHaveBeenCalledTimes(1)
})

test('submitting a short PIN does nothing', async () => {
  const { field, onUnlockWithPin } = renderPinUnlock()
  await fireEvent.input(field, { target: { value: '4729' } })
  await fireEvent.submit(field.form as HTMLFormElement)
  expect(onUnlockWithPin).not.toHaveBeenCalled()
})

test('says which command a waiting terminal wants and clears when the wait ends', async () => {
  const rendered = render(UnlockScreen, { props: { status, onUnlockWithPin: vi.fn(), onUnlockWithHello: vi.fn(), onSubmitMasterPassword: vi.fn(), terminalWaiting: { command: 'get', field: 'password', copy: false, terminal: 'pts/3', remote: true } } } as never)
  const waiting = screen.getByRole('status')
  expect(waiting.textContent).toBe('A terminal wants the password of an item. Sesame asks you about it after you unlock. It came through a remote login.')
  await rendered.rerender({ terminalWaiting: null })
  expect(waiting.isConnected).toBe(false)
  expect(screen.queryByText(/A terminal wants/)).toBeNull()
})

/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { ServerInspection, ServiceConnectionStatus } from '../types'
import CustomServerSetting from './CustomServerSetting.svelte'

afterEach(cleanup)

const FINGERPRINT = '0123456789abcdef'.repeat(4)
const DISCONNECTED: ServiceConnectionStatus = { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }
const INSPECTION: ServerInspection = { address: 'https://sesame.example.test/vault', name: 'Home server', version: '1.0.0', fingerprint: FINGERPRINT, fingerprintInLink: true, codeInLink: true, plainHttp: false }

function renderSetting(overrides: Record<string, unknown> = {}) {
  const props = {
    connection: DISCONNECTED,
    working: false,
    available: true,
    onInspect: vi.fn().mockResolvedValue(INSPECTION),
    onConnect: vi.fn().mockResolvedValue(true),
    onDisconnect: vi.fn(),
    onRefresh: vi.fn(),
    ...overrides,
  }
  render(CustomServerSetting, props)
  return props
}

async function typeInto(label: string, value: string) {
  await fireEvent.input(screen.getByLabelText(label), { target: { value } })
}

test('a link with a code needs no second field', async () => {
  renderSetting()
  await typeInto('Pairing link or server address', 'https://sesame.example.test/pair#code=abc&fp=def')
  expect(screen.queryByLabelText('One-time pairing code')).toBeNull()
  expect((screen.getByRole('button', { name: 'Check server' }) as HTMLButtonElement).disabled).toBe(false)
})

test('a plain address asks for the code and stays disabled without it', async () => {
  renderSetting()
  await typeInto('Pairing link or server address', 'https://sesame.example.test')
  expect((screen.getByRole('button', { name: 'Check server' }) as HTMLButtonElement).disabled).toBe(true)
  await typeInto('One-time pairing code', 'abc')
  expect((screen.getByRole('button', { name: 'Check server' }) as HTMLButtonElement).disabled).toBe(false)
})

test('nothing is paired until the full address and fingerprint are shown and confirmed', async () => {
  const props = renderSetting()
  await typeInto('Pairing link or server address', 'https://sesame.example.test/vault/pair#code=abc')
  await fireEvent.click(screen.getByRole('button', { name: 'Check server' }))
  await waitFor(() => expect(screen.getByText('https://sesame.example.test/vault')).toBeTruthy())
  expect(props.onInspect).toHaveBeenCalledWith('https://sesame.example.test/vault/pair#code=abc')
  expect(props.onConnect).not.toHaveBeenCalled()
  expect(screen.getByText('01234567 89abcdef 01234567 89abcdef 01234567 89abcdef 01234567 89abcdef')).toBeTruthy()
  expect(screen.getByText('The fingerprint matches the one in your pairing link.')).toBeTruthy()

  await fireEvent.click(screen.getByRole('button', { name: 'Pair with this server' }))
  await waitFor(() => expect(props.onConnect).toHaveBeenCalledTimes(1))
  expect(props.onConnect).toHaveBeenCalledWith('https://sesame.example.test/vault/pair#code=abc', '', FINGERPRINT)
})

test('a link without a fingerprint warns the person to compare it', async () => {
  renderSetting({ onInspect: vi.fn().mockResolvedValue({ ...INSPECTION, fingerprintInLink: false }) })
  await typeInto('Pairing link or server address', 'https://sesame.example.test')
  await typeInto('One-time pairing code', 'abc')
  await fireEvent.click(screen.getByRole('button', { name: 'Check server' }))
  await waitFor(() => expect(screen.getByText(/did not include a fingerprint/)).toBeTruthy())
})

test('cancelling returns to the form without pairing', async () => {
  const props = renderSetting()
  await typeInto('Pairing link or server address', 'https://sesame.example.test/pair#code=abc')
  await fireEvent.click(screen.getByRole('button', { name: 'Check server' }))
  await waitFor(() => screen.getByRole('button', { name: 'Cancel' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(screen.getByLabelText('Pairing link or server address')).toBeTruthy()
  expect(props.onConnect).not.toHaveBeenCalled()
})

test('a refused inspection stays on the form', async () => {
  renderSetting({ onInspect: vi.fn().mockResolvedValue(null) })
  await typeInto('Pairing link or server address', 'https://sesame.example.test/pair#code=abc')
  await fireEvent.click(screen.getByRole('button', { name: 'Check server' }))
  await waitFor(() => expect(screen.getByLabelText('Pairing link or server address')).toBeTruthy())
  expect(screen.queryByRole('button', { name: 'Pair with this server' })).toBeNull()
})

test('a failed pairing keeps the confirmation open', async () => {
  const props = renderSetting({ onConnect: vi.fn().mockResolvedValue(false) })
  await typeInto('Pairing link or server address', 'https://sesame.example.test/pair#code=abc')
  await fireEvent.click(screen.getByRole('button', { name: 'Check server' }))
  await waitFor(() => screen.getByRole('button', { name: 'Pair with this server' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Pair with this server' }))
  await waitFor(() => expect(props.onConnect).toHaveBeenCalled())
  expect(screen.getByRole('button', { name: 'Pair with this server' })).toBeTruthy()
})

test('a connected custom server shows its address and pinned fingerprint and can be disconnected', async () => {
  const props = renderSetting({
    connection: { ...DISCONNECTED, state: 'connected', connected: true, online: true, deviceName: 'Linux desktop', serverAddress: 'https://sesame.example.test', serverFingerprint: FINGERPRINT, serverName: 'Home server' },
  })
  expect(screen.getByText('https://sesame.example.test')).toBeTruthy()
  expect(screen.getByText('01234567 89abcdef 01234567 89abcdef 01234567 89abcdef 01234567 89abcdef')).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }))
  expect(props.onDisconnect).toHaveBeenCalled()
  expect(screen.queryByLabelText('Pairing link or server address')).toBeNull()
})

test('a changed server key is reported and offers to remove the link', async () => {
  renderSetting({
    connection: { ...DISCONNECTED, state: 'serverKeyChanged', connected: true, online: true, deviceName: 'Linux desktop', serverAddress: 'https://sesame.example.test', serverFingerprint: FINGERPRINT },
  })
  expect(screen.getByText(/different key than the one this desktop pinned/)).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Remove link' })).toBeTruthy()
})

test('a desktop linked to an account must disconnect it first', () => {
  renderSetting({ connection: { ...DISCONNECTED, state: 'connected', connected: true, online: true, deviceName: 'Linux desktop' } })
  expect(screen.getByText(/Disconnect it before pairing/)).toBeTruthy()
  expect(screen.queryByLabelText('Pairing link or server address')).toBeNull()
})

test('preview mode explains that pairing needs the installed app', () => {
  renderSetting({ available: false })
  expect(screen.getByText(/available in the installed desktop app/)).toBeTruthy()
  expect(screen.queryByLabelText('Pairing link or server address')).toBeNull()
})

test('a code typed earlier is cleared and never sent when a pasted link carries its own code', async () => {
  const props = renderSetting()
  await typeInto('Pairing link or server address', 'https://sesame.example.test')
  await typeInto('One-time pairing code', 'stale-code-from-an-earlier-attempt')
  await typeInto('Pairing link or server address', 'https://sesame.example.test/pair#code=abcdefghijklmnopqrstuvwxyz0123456789')
  expect(screen.queryByLabelText('One-time pairing code')).toBeNull()
  await fireEvent.click(screen.getByRole('button', { name: 'Check server' }))
  await waitFor(() => screen.getByRole('button', { name: 'Pair with this server' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Pair with this server' }))
  await waitFor(() => expect(props.onConnect).toHaveBeenCalledTimes(1))
  expect(props.onConnect).toHaveBeenCalledWith('https://sesame.example.test/pair#code=abcdefghijklmnopqrstuvwxyz0123456789', '', FINGERPRINT)
})

test('the typed code is empty again when the link is replaced by a bare address', async () => {
  renderSetting()
  await typeInto('Pairing link or server address', 'https://sesame.example.test')
  await typeInto('One-time pairing code', 'abc')
  await typeInto('Pairing link or server address', 'https://sesame.example.test/pair#code=abcdefghijklmnopqrstuvwxyz0123456789')
  await typeInto('Pairing link or server address', 'https://sesame.example.test')
  expect((screen.getByLabelText('One-time pairing code') as HTMLInputElement).value).toBe('')
})

test('the connected row says what the fingerprint is, and claims nothing more', () => {
  renderSetting({
    connection: { ...DISCONNECTED, state: 'connected', connected: true, online: true, deviceName: 'Linux desktop', serverAddress: 'https://sesame.example.test', serverFingerprint: FINGERPRINT },
  })
  expect(screen.getByText('Fingerprint you confirmed')).toBeTruthy()
  expect(document.body.textContent).not.toMatch(/verified|authenticated|secure|trusted/i)
})

test('a server clock that differs from this computer is explained', () => {
  renderSetting({
    connection: { ...DISCONNECTED, state: 'serverClockDiffers', connected: true, online: true, deviceName: 'Linux desktop', serverAddress: 'https://sesame.example.test', serverFingerprint: FINGERPRINT },
  })
  expect(screen.getByText(/clock/)).toBeTruthy()
})

test('after a removed link the form says why the desktop was disconnected', () => {
  renderSetting({ connection: { ...DISCONNECTED, state: 'expired' } })
  expect(screen.getByText(/expired/)).toBeTruthy()
})

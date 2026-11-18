/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { platformCapabilities } from '../platform'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { TerminalAllowanceList, TerminalToolStatus } from '../terminal-api'
import type { PlatformCapabilities, VaultSnapshot } from '../types'
import TerminalAccessSetting from './TerminalAccessSetting.svelte'

const terminalApi = vi.hoisted(() => ({
  getTerminalStatus: vi.fn(),
  listTerminalPermissions: vi.fn(),
  forgetTerminalPermissions: vi.fn(),
  onTerminalPermissionsChanged: vi.fn(),
  onTerminalStatusChanged: vi.fn(),
}))

vi.mock('../terminal-api', () => terminalApi)

const ready: TerminalToolStatus = { supported: true, available: true, servedElsewhere: false, code: 'ready' }
const empty: TerminalAllowanceList = { allowances: [], requests: [] }
let permissionsChanged: () => void = () => {}
let statusChanged: (status: TerminalToolStatus) => void = () => {}

function capabilities(os: string): PlatformCapabilities {
  return { os, pinUnlock: false, biometricUnlock: false, autoType: false, browserIntegration: false, sessionAutoLock: false, systemIdle: false, screenLockMonitoring: false, quickAccessShortcut: false, accountLinking: false, desktopUpdates: false, windowControls: false }
}

beforeEach(() => {
  vi.useFakeTimers()
  for (const mock of Object.values(terminalApi)) mock.mockReset()
  platformCapabilities.set(capabilities('linux'))
  terminalApi.getTerminalStatus.mockResolvedValue(ready)
  terminalApi.listTerminalPermissions.mockResolvedValue(empty)
  terminalApi.forgetTerminalPermissions.mockResolvedValue(undefined)
  terminalApi.onTerminalPermissionsChanged.mockImplementation(async (handler) => { permissionsChanged = handler; return () => {} })
  terminalApi.onTerminalStatusChanged.mockImplementation(async (handler) => { statusChanged = handler; return () => {} })
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

function renderSetting() {
  const stores = createAppStores()
  stores.vault.patch({ snapshot: { entries: [{ id: 'northwind', title: 'Northwind mail', site: 'mail.northwind.example', initials: 'N', folder: '', favourite: false, updatedAt: 0, tags: [], issueKinds: [] }], items: [] } as unknown as VaultSnapshot })
  render(TerminalAccessSetting, { context: new Map([[APP_STORES, stores]]) } as never)
}

test('says the tool is ready and that nothing is allowed yet', async () => {
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('Ready')).toBeTruthy()
  expect(screen.getByText(/Run sesame list, sesame get or sesame totp/)).toBeTruthy()
  expect(screen.getByText(/No terminal is allowed right now/)).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Forget' }) as HTMLButtonElement).disabled).toBe(true)
})

test('lists allowed terminals with their time and the requests answered without asking, then forgets them', async () => {
  terminalApi.listTerminalPermissions.mockResolvedValueOnce({
    allowances: [{ terminal: 'pts/3', program: { reportedName: 'bash‮' }, remote: true, expiresInMs: 125_000 }],
    requests: [{ at: 1_800_000_000, terminal: 'pts/3', command: 'get', itemId: 'northwind', itemKind: 'login', field: 'username' }],
  })
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getAllByText('pts/3', { selector: 'li code bdi' })).toHaveLength(2)
  const scope = document.querySelector('.terminal-program')?.textContent
  expect(scope).toBe('Covers this terminal and anything started from it. The program that asked named itself bash?.')
  expect(screen.getByText('Remote session')).toBeTruthy()
  expect(screen.getByText('Allowed for 2 more minutes')).toBeTruthy()
  expect(screen.getByText('Read the username of Northwind mail')).toBeTruthy()

  await vi.advanceTimersByTimeAsync(70_000)
  expect(screen.getByText('Allowed for 55 more seconds')).toBeTruthy()

  await fireEvent.click(screen.getByRole('button', { name: 'Forget' }))
  await vi.advanceTimersByTimeAsync(0)
  expect(terminalApi.forgetTerminalPermissions).toHaveBeenCalledTimes(1)
  expect(screen.getByText(/No terminal is allowed right now/)).toBeTruthy()
})

test('an allowance drops out of the list when its time runs out', async () => {
  terminalApi.listTerminalPermissions.mockResolvedValueOnce({ allowances: [{ terminal: 'pts/9', remote: false, expiresInMs: 2_000 }], requests: [] })
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('Allowed for 2 more seconds')).toBeTruthy()
  await vi.advanceTimersByTimeAsync(3_000)
  expect(screen.queryByText(/Allowed for/)).toBeNull()
  expect(terminalApi.listTerminalPermissions).toHaveBeenCalledTimes(2)
})

test('reloads when Sesame reports a change to the permissions or the listener', async () => {
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  terminalApi.listTerminalPermissions.mockResolvedValueOnce({ allowances: [{ terminal: 'pts/4', remote: false, expiresInMs: 300_000 }], requests: [] })
  permissionsChanged()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('Allowed for 5 more minutes')).toBeTruthy()
  statusChanged({ supported: true, available: false, servedElsewhere: true, code: 'servedElsewhere' })
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('Used by another Sesame')).toBeTruthy()
  expect(screen.getByText(/Another Sesame on this computer already answers the command line tool/)).toBeTruthy()
})

test('says when listening failed', async () => {
  terminalApi.getTerminalStatus.mockResolvedValue({ supported: true, available: false, servedElsewhere: false, code: 'failed' })
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('Not running')).toBeTruthy()
  expect(screen.getByText(/could not start listening/)).toBeTruthy()
})

test('on Windows it says every request asks and offers no allowance list', async () => {
  platformCapabilities.set(capabilities('windows'))
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('On Windows, Sesame asks in this window every time a terminal makes a request.')).toBeTruthy()
  expect(screen.queryByText('Allowed terminals')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Forget' })).toBeNull()
})

test('a failed permission read says so, keeps Forget available and offers to try again', async () => {
  terminalApi.listTerminalPermissions.mockRejectedValueOnce(new Error('Sesame could not read the terminal permissions.'))
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.queryByText(/No terminal is allowed right now/)).toBeNull()
  expect(screen.getByText('Sesame could not read which terminals are allowed.')).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Forget' }) as HTMLButtonElement).disabled).toBe(false)

  await fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText(/No terminal is allowed right now/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
})

test.each(['permissions', 'status'] as const)('the %s read waits only for its own listener', async (first) => {
  let permissionsReady: (stop: () => void) => void = () => {}
  let statusReady: (stop: () => void) => void = () => {}
  terminalApi.onTerminalPermissionsChanged.mockImplementation((handler) => { permissionsChanged = handler; return new Promise((resolve) => { permissionsReady = resolve }) })
  terminalApi.onTerminalStatusChanged.mockImplementation((handler) => { statusChanged = handler; return new Promise((resolve) => { statusReady = resolve }) })
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(terminalApi.listTerminalPermissions).not.toHaveBeenCalled()
  expect(terminalApi.getTerminalStatus).not.toHaveBeenCalled()
  const [ready, read, other, otherRead] = first === 'permissions'
    ? [permissionsReady, terminalApi.listTerminalPermissions, statusReady, terminalApi.getTerminalStatus]
    : [statusReady, terminalApi.getTerminalStatus, permissionsReady, terminalApi.listTerminalPermissions]
  ready(() => {})
  await vi.advanceTimersByTimeAsync(0)
  expect(read).toHaveBeenCalledTimes(1)
  expect(otherRead).not.toHaveBeenCalled()
  other(() => {})
  await vi.advanceTimersByTimeAsync(0)
  expect(otherRead).toHaveBeenCalledTimes(1)
})

test('a status event newer than the first status read is kept', async () => {
  let answerStatus: (status: TerminalToolStatus) => void = () => {}
  terminalApi.getTerminalStatus.mockReturnValueOnce(new Promise((resolve) => { answerStatus = resolve }))
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  statusChanged(ready)
  answerStatus({ supported: true, available: false, servedElsewhere: false, code: 'starting' })
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText('Ready')).toBeTruthy()
})

test('a failed refresh after an empty list keeps Forget available, and a later success clears the error', async () => {
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect((screen.getByRole('button', { name: 'Forget' }) as HTMLButtonElement).disabled).toBe(true)
  terminalApi.listTerminalPermissions.mockRejectedValueOnce(new Error('Sesame could not read the terminal permissions.'))
  permissionsChanged()
  await vi.advanceTimersByTimeAsync(0)
  expect((screen.getByRole('button', { name: 'Forget' }) as HTMLButtonElement).disabled).toBe(false)
  expect(screen.queryByText(/No terminal is allowed right now/)).toBeNull()
  expect(screen.getByText('Sesame could not read the terminal permissions.')).toBeTruthy()
  permissionsChanged()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.queryByText('Sesame could not read the terminal permissions.')).toBeNull()
  expect(screen.getByText(/No terminal is allowed right now/)).toBeTruthy()
})

test('a read that began before Forget cannot bring the forgotten terminal back', async () => {
  const allowed = { allowances: [{ terminal: 'pts/6', remote: false, expiresInMs: 200_000 }], requests: [] }
  terminalApi.listTerminalPermissions.mockResolvedValueOnce(allowed)
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText(/Allowed for/)).toBeTruthy()
  let answerStale: (list: TerminalAllowanceList) => void = () => {}
  terminalApi.listTerminalPermissions.mockReturnValueOnce(new Promise((resolve) => { answerStale = resolve }))
  permissionsChanged()
  await vi.advanceTimersByTimeAsync(0)
  await fireEvent.click(screen.getByRole('button', { name: 'Forget' }))
  await vi.advanceTimersByTimeAsync(0)
  answerStale(allowed)
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.queryByText(/Allowed for/)).toBeNull()
  expect(screen.getByText(/No terminal is allowed right now/)).toBeTruthy()
})

test('terminals whose names and positions run together are each listed', async () => {
  const allowances = Array.from({ length: 12 }, (_, index) => ({ terminal: index === 1 ? 'pts/11' : index === 11 ? 'pts/1' : `pts/${20 + index}`, remote: false, expiresInMs: 200_000 }))
  terminalApi.listTerminalPermissions.mockResolvedValueOnce({ allowances, requests: [] })
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getAllByText(/Allowed for/)).toHaveLength(12)
})

test('the countdown follows elapsed time, not the wall clock', async () => {
  terminalApi.listTerminalPermissions.mockResolvedValueOnce({ allowances: [{ terminal: 'pts/5', remote: false, expiresInMs: 30_000 }], requests: [] })
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  vi.setSystemTime(Date.now() - 120_000)
  await vi.advanceTimersByTimeAsync(1_000)
  expect(screen.getByText('Allowed for 29 more seconds')).toBeTruthy()
})

test('says that an allowed terminal skips the question only when nothing more is needed', async () => {
  renderSetting()
  await vi.advanceTimersByTimeAsync(0)
  expect(screen.getByText(/A terminal you allowed is answered without asking, unless the request needs your master password or a choice between items\./)).toBeTruthy()
})

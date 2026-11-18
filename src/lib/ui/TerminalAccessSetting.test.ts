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
  expect(screen.getByText('bash?')).toBeTruthy()
  expect(screen.getByText('Remote session')).toBeTruthy()
  expect(screen.getByText('Allowed for 3 more minutes')).toBeTruthy()
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

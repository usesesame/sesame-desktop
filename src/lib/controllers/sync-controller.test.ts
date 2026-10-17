/* @vitest-environment jsdom */
import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createSyncController, describeSyncForChrome } from './sync-controller'

const core = vi.hoisted(() => ({ invoke: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => core)

const status = (overrides: Record<string, unknown> = {}) => ({
  enrolled: true,
  state: 'approved',
  vaultEpoch: 1,
  revision: 3,
  devices: [{ deviceId: 'd1', label: 'Laptop', state: 'approved', isThisDevice: true, addedIndex: 1 }],
  needsNewKey: false,
  alarm: null,
  confirmedAt: null,
  ...overrides,
})

const idle = { phase: 'idle', halt: '', conflictRevision: 0, pending: false, lastSuccessRevision: 3, consecutiveFailures: 0 }

function answer(responses: Record<string, unknown>) {
  core.invoke.mockImplementation(async (command: string) => {
    if (!(command in responses)) return {}
    const value = responses[command]
    if (value instanceof Error) throw value.message
    return typeof value === 'function' ? (value as () => unknown)() : value
  })
}

describe('the Sync preview controller', () => {
  beforeEach(() => {
    core.invoke.mockReset()
    localStorage.clear()
    vi.useRealTimers()
  })

  it('shows the state and devices Rust verified', async () => {
    answer({ sync_status: status(), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.refresh()
    const state = get(sync)
    expect(state.state).toBe('approved')
    expect(state.devices).toHaveLength(1)
    expect(state.alarm).toBe('')
  })

  it('shows when another device last confirmed the vault, and nothing when none has', async () => {
    answer({ sync_status: status({ confirmedAt: 1_800_000_000 }), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.refresh()
    expect(get(sync).confirmedAt).toBe(1_800_000_000)
    answer({ sync_status: status(), sync_coordinator_status: idle })
    await sync.refresh()
    expect(get(sync).confirmedAt).toBe(0)
  })

  it('keeps a disagreement between devices as an alarm and applies nothing', async () => {
    answer({ sync_status: status({ alarm: 'the service shows a different revision.' }), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.refresh()
    expect(get(sync).alarm).toContain('different revision')
    core.invoke.mockClear()
    await sync.autoSync()
    expect(core.invoke).not.toHaveBeenCalledWith('sync_now')
  })

  it('does not sync by itself while the device needs the new key, is halted, or is not active', async () => {
    for (const overrides of [{ needsNewKey: true }, { state: 'removed' }, { state: 'no_vault', enrolled: false }]) {
      answer({ sync_status: status(overrides), sync_coordinator_status: idle })
      const sync = createSyncController()
      await sync.refresh()
      core.invoke.mockClear()
      await sync.autoSync()
      expect(core.invoke).not.toHaveBeenCalled()
    }
    answer({ sync_status: status(), sync_coordinator_status: { ...idle, phase: 'halted', halt: 'conflict' } })
    const halted = createSyncController()
    await halted.refresh()
    core.invoke.mockClear()
    await halted.autoSync()
    expect(core.invoke).not.toHaveBeenCalled()
  })

  it('syncs by itself when the device is active and nothing is wrong', async () => {
    answer({ sync_status: status(), sync_coordinator_status: idle, sync_now: idle })
    const sync = createSyncController()
    await sync.refresh()
    core.invoke.mockClear()
    await sync.autoSync()
    expect(core.invoke).toHaveBeenCalledWith('sync_now')
  })

  it('turns Sync on by creating the vault and then uploading it', async () => {
    answer({ sync_create_vault: status(), sync_status: status(), sync_coordinator_status: idle, sync_upload_vault: { revision: 1, vaultEpoch: 1, entryCount: 2 } })
    const sync = createSyncController()
    await sync.enable('Kitchen laptop')
    const commands = core.invoke.mock.calls.map((call) => call[0])
    expect(commands.indexOf('sync_create_vault')).toBeGreaterThanOrEqual(0)
    expect(commands.indexOf('sync_upload_vault')).toBeGreaterThan(commands.indexOf('sync_create_vault'))
    expect(core.invoke).toHaveBeenCalledWith('sync_create_vault', { label: 'Kitchen laptop' })
  })

  it('turns a fork reported by Rust into the alarm', async () => {
    answer({ sync_upload_vault: new Error('sync_fork:the service shows a different revision.') })
    const sync = createSyncController()
    await sync.push()
    expect(get(sync).alarm).toBe('the service shows a different revision.')
    expect(get(sync).error).toBe('')
  })

  it('opens the conflict screen when an upload loses', async () => {
    answer({ sync_upload_vault: new Error('sync_conflict:7'), sync_conflict_details: { thisDevice: { deviceLabel: 'This device', revision: 5, changedAt: '', entryCount: 2 }, otherDevice: { deviceLabel: 'Laptop', revision: 7, changedAt: '', entryCount: 3 } } })
    const sync = createSyncController()
    await sync.push()
    expect(get(sync).conflictOpen).toBe(true)
  })

  it('shows a pairing code, waits for the other device, and cancels cleanly', async () => {
    let finish: (value: unknown) => void = () => undefined
    answer({
      sync_pairing_code: { code: 'K7Q2MHX9PD', expiresInSeconds: 540 },
      sync_approve_with_code: () => new Promise((resolve) => { finish = resolve }),
      sync_cancel_pairing: {},
      sync_status: status(),
      sync_coordinator_status: idle,
    })
    const sync = createSyncController()
    const pairing = sync.openPairing()
    await vi.waitFor(() => expect(get(sync).pairingCode).toBe('K7Q2MHX9PD'))
    expect(get(sync).pairingPhase).toBe('waiting')
    finish({ label: 'Phone' })
    await pairing
    expect(get(sync).pairingPhase).toBe('done')
    expect(get(sync).pairingDone).toBe('Phone')
    expect(get(sync).pairingCode).toBe('')
    await sync.closePairing()
    expect(core.invoke).toHaveBeenCalledWith('sync_cancel_pairing')
    expect(get(sync).pairingOpen).toBe(false)
  })

  it('never keeps the recovery kit after it is dismissed', async () => {
    answer({ sync_join_with_code: { recoveryKit: 'FICTIONAL-KIT' }, sync_status: status(), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.join('K7Q2MHX9PD', 'Phone', 'fictional password')
    expect(get(sync).removalRecoveryKit).toBe('FICTIONAL-KIT')
    sync.dismissRecoveryKit()
    expect(get(sync).removalRecoveryKit).toBe('')
  })
})

describe('what the window shows about Sync', () => {
  const base = { enrolled: true, state: 'approved', activity: 'idle' as const, alarm: '', needsNewKey: false }

  it('says nothing for a vault that is not synced, so the bar keeps saying Local vault', () => {
    expect(describeSyncForChrome({ ...base, enrolled: false, state: 'not_enrolled' })).toBeUndefined()
    expect(describeSyncForChrome({ ...base, state: 'pairing' })).toBeUndefined()
    expect(describeSyncForChrome({ ...base, state: 'removed' })).toBeUndefined()
  })

  it('names the synced vault and what it is doing, with a colour that means a state', () => {
    expect(describeSyncForChrome(base)).toEqual({ label: 'Synced vault', tone: 'ok' })
    expect(describeSyncForChrome({ ...base, activity: 'synced' })).toEqual({ label: 'Synced vault · Up to date', tone: 'ok' })
    expect(describeSyncForChrome({ ...base, activity: 'syncing' })).toEqual({ label: 'Synced vault · Syncing…', tone: 'busy' })
    expect(describeSyncForChrome({ ...base, activity: 'offline' })?.tone).toBe('warn')
    expect(describeSyncForChrome({ ...base, activity: 'attention' })?.tone).toBe('warn')
  })

  it('puts a disagreement or a missing key ahead of any other status', () => {
    expect(describeSyncForChrome({ ...base, activity: 'synced', alarm: 'x' })?.label).toMatch(/Devices disagree/)
    expect(describeSyncForChrome({ ...base, activity: 'synced', needsNewKey: true })?.label).toMatch(/new key/)
  })
})

describe('knowing at once whether this vault is synced', () => {
  it('starts from what was known last time, so the first paint is already right', () => {
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: true, state: 'approved' }))
    const sync = createSyncController()
    expect(get(sync).enrolled).toBe(true)
    expect(get(sync).state).toBe('approved')
    expect(core.invoke).not.toHaveBeenCalled()
  })

  it('ignores a damaged cache', () => {
    localStorage.setItem('sesame-sync-cache-v1', '{not json')
    expect(get(createSyncController()).enrolled).toBe(false)
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: 'yes', state: 7 }))
    expect(get(createSyncController()).enrolled).toBe(false)
  })

  it('reads the local files without the network and remembers the answer', async () => {
    answer({ sync_local_status: { state: 'approved', revision: 4 } })
    const sync = createSyncController()
    await sync.loadLocal()
    expect(get(sync).state).toBe('approved')
    expect(core.invoke).toHaveBeenCalledTimes(1)
    expect(JSON.parse(localStorage.getItem('sesame-sync-cache-v1') ?? '{}')).toEqual({ enrolled: true, state: 'approved' })
    answer({ sync_local_status: { state: 'not_enrolled', revision: 0 } })
    await sync.loadLocal()
    expect(get(sync).enrolled).toBe(false)
    expect(JSON.parse(localStorage.getItem('sesame-sync-cache-v1') ?? '{}')).toEqual({ enrolled: false, state: 'not_enrolled' })
  })

  it('keeps the cached answer when the local read fails', async () => {
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: true, state: 'approved' }))
    answer({ sync_local_status: new Error('unreadable') })
    const sync = createSyncController()
    await sync.loadLocal()
    expect(get(sync).state).toBe('approved')
  })

  it('writes what the service says after a full refresh', async () => {
    answer({ sync_status: status({ state: 'removed' }), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.refresh()
    expect(JSON.parse(localStorage.getItem('sesame-sync-cache-v1') ?? '{}')).toEqual({ enrolled: true, state: 'removed' })
  })
})

describe('syncing without being asked', () => {
  const approved = () => {
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: true, state: 'approved' }))
    return createSyncController()
  }

  it('shows syncing while it runs and up to date afterwards', async () => {
    let finish: (value: unknown) => void = () => {}
    core.invoke.mockImplementation((command: string) => (command === 'sync_now' ? new Promise((resolve) => { finish = resolve }) : Promise.resolve(idle)))
    const sync = approved()
    const running = sync.autoSync()
    expect(get(sync).activity).toBe('syncing')
    finish(idle)
    await running
    expect(get(sync).activity).toBe('synced')
    expect(get(sync).lastSyncedAt).toBeGreaterThan(0)
  })

  it('does not start a second run while one is going', async () => {
    core.invoke.mockImplementation(() => new Promise(() => {}))
    const sync = approved()
    void sync.autoSync()
    await sync.autoSync()
    expect(core.invoke.mock.calls.filter((call) => call[0] === 'sync_now')).toHaveLength(1)
  })

  it('shows offline when the run cannot finish, and halted states as needing attention', async () => {
    answer({ sync_now: new Error('Sesame could not reach Sesame Sync.') })
    const offline = approved()
    await offline.autoSync()
    expect(get(offline).activity).toBe('offline')
    answer({ sync_now: { ...idle, phase: 'halted', halt: 'revoked' } })
    const halted = approved()
    await halted.autoSync()
    expect(get(halted).activity).toBe('attention')
  })

  it('syncs once, a moment after the last change, and only on a synced device', async () => {
    vi.useFakeTimers()
    answer({ sync_local_status: { state: 'approved', revision: 2, unsynced: false }, sync_now: idle })
    const sync = approved()
    sync.vaultChanged()
    sync.vaultChanged()
    sync.vaultChanged()
    expect(core.invoke.mock.calls.filter((call) => call[0] === 'sync_now')).toHaveLength(0)
    await vi.advanceTimersByTimeAsync(700)
    expect(core.invoke.mock.calls.filter((call) => call[0] === 'sync_now')).toHaveLength(1)

    core.invoke.mockClear()
    const local = createSyncController()
    localStorage.clear()
    const notSynced = createSyncController()
    notSynced.vaultChanged()
    await vi.advanceTimersByTimeAsync(5000)
    expect(core.invoke).not.toHaveBeenCalled()
    expect(get(local).enrolled).toBe(true)
  })

  it('shows that changes are not synced the moment the vault changes, then up to date after the sync', async () => {
    vi.useFakeTimers()
    let unsynced = true
    answer({ sync_local_status: () => ({ state: 'approved', revision: 2, unsynced }), sync_now: () => { unsynced = false; return idle } })
    const sync = approved()
    sync.vaultChanged()
    await vi.advanceTimersByTimeAsync(5)
    expect(get(sync).activity).toBe('pending')
    expect(describeSyncForChrome(get(sync))?.label).toBe('Synced vault · Changes not synced yet')
    await vi.advanceTimersByTimeAsync(700)
    expect(get(sync).activity).toBe('synced')
  })

  it('clears the pending mark when the vault matches the last sync again', async () => {
    vi.useFakeTimers()
    let unsynced = true
    answer({ sync_local_status: () => ({ state: 'approved', revision: 2, unsynced }) })
    const sync = approved()
    await sync.loadLocal()
    expect(get(sync).activity).toBe('pending')
    unsynced = false
    await sync.loadLocal()
    expect(get(sync).activity).toBe('synced')
  })

  it('syncs again after a run that was going when the vault changed', async () => {
    const finishers: Array<(value: unknown) => void> = []
    core.invoke.mockImplementation((command: string) => (command === 'sync_now' ? new Promise((resolve) => { finishers.push(resolve) }) : Promise.resolve(idle)))
    const sync = approved()
    const first = sync.autoSync()
    await sync.autoSync()
    finishers[0](idle)
    await first
    await Promise.resolve()
    expect(finishers).toHaveLength(2)
    finishers[1](idle)
  })

  it('reads the local state, then syncs on a timer and when the window gets focus, until stopped', async () => {
    vi.useFakeTimers()
    answer({ sync_local_status: { state: 'approved', revision: 2 }, sync_now: idle })
    const sync = approved()
    const stop = sync.startBackground()
    await vi.advanceTimersByTimeAsync(10)
    const commands = () => core.invoke.mock.calls.map((call) => call[0])
    expect(commands().slice(0, 2)).toEqual(['sync_local_status', 'sync_now'])
    core.invoke.mockClear()
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000 + 10)
    expect(commands()).toContain('sync_now')
    core.invoke.mockClear()
    window.dispatchEvent(new Event('focus'))
    await vi.advanceTimersByTimeAsync(10)
    expect(commands()).toContain('sync_now')
    stop()
    core.invoke.mockClear()
    window.dispatchEvent(new Event('focus'))
    await vi.advanceTimersByTimeAsync(10 * 60 * 1000)
    expect(core.invoke).not.toHaveBeenCalled()
  })
})

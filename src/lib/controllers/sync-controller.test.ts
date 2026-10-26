/* @vitest-environment jsdom */
import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { autoSyncBackoffMs, createSyncController, describeCoordinatorState, describeFloorCheck, describeSyncForChrome } from './sync-controller'

const core = vi.hoisted(() => ({ invoke: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => core)

const status = (overrides: Record<string, unknown> = {}) => ({
  enrolled: true,
  state: 'approved',
  vaultEpoch: 1,
  revision: 3,
  devices: [{ deviceId: 'd1', label: 'Laptop', state: 'approved', isThisDevice: true, addedIndex: 1, newerKey: false }],
  needsNewKey: false,
  alarm: null,
  confirmedAt: null,
  floorConfirmedAt: null,
  ...overrides,
})

const idle = { phase: 'idle', halt: '', conflictRevision: 0, pending: false, lastSuccessRevision: 3, consecutiveFailures: 0, downloadsApplied: 0 }

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

  it('offers to allow the older key exchange only after a device was refused for it, and sends the choice with the retry', async () => {
    const refusal = 'This device only supports the older key exchange, and this vault already uses the newer one. Update Sesame on the new device, or allow the older key exchange and try again.'
    let refused = false
    const approve = () => {
      if (!refused) {
        refused = true
        throw refusal
      }
      return { label: 'Old laptop' }
    }
    answer({ sync_pairing_code: { code: 'K7Q2MHX9PD', expiresInSeconds: 540 }, sync_approve_with_code: approve, sync_cancel_pairing: {}, sync_status: status(), sync_coordinator_status: idle })
    const approveCalls = () => core.invoke.mock.calls.filter((call) => call[0] === 'sync_approve_with_code').map((call) => call[1])
    const sync = createSyncController()
    await sync.openPairing()
    expect(get(sync).olderKeyRefused).toBe(true)
    expect(approveCalls()).toEqual([{ allowClassical: false }])

    sync.setAllowOlderKeys(true)
    await sync.openPairing()
    expect(approveCalls()).toEqual([{ allowClassical: false }, { allowClassical: true }])
    expect(get(sync).pairingPhase).toBe('done')
    expect(get(sync).olderKeyRefused).toBe(false)
  })

  it('forgets the allowance when the pairing window is closed', async () => {
    answer({ sync_cancel_pairing: {}, sync_status: status(), sync_coordinator_status: idle })
    const sync = createSyncController()
    sync.setAllowOlderKeys(true)
    await sync.closePairing()
    expect(get(sync).allowOlderKeys).toBe(false)
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
    expect(get(sync).pairingPhase).toBe('starting')
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

describe('changing keys', () => {
  beforeEach(() => {
    core.invoke.mockReset()
    localStorage.clear()
  })

  it('upgrades this device and then reloads what Rust verified', async () => {
    answer({ sync_status: status(), sync_coordinator_status: idle, sync_upgrade_device_key: {} })
    const sync = createSyncController()
    await sync.upgradeDeviceKey()
    expect(core.invoke).toHaveBeenCalledWith('sync_upgrade_device_key')
    expect(get(sync).lastTransfer).toBe('This device now has the newer key.')
    expect(get(sync).loadError).toBe('')
  })

  it('shows the reason in plain words when the key upgrade is refused', async () => {
    const refusal = 'This Sync server does not accept the newer device keys yet.'
    answer({ sync_upgrade_device_key: new Error(refusal) })
    const sync = createSyncController()
    await sync.upgradeDeviceKey()
    expect(get(sync).loadError).toBe(refusal)
    expect(get(sync).working).toBe(false)
  })

  it('shows the new recovery kit before the vault key changes and sends no kit back afterwards', async () => {
    answer({ sync_status: status(), sync_coordinator_status: idle, sync_prepare_key_change: { recoveryKit: 'FICTIONAL-KIT' }, sync_rotate_vault_key: {} })
    const sync = createSyncController()
    await sync.prepareKeyChange('fictional master password')
    expect(core.invoke).toHaveBeenCalledWith('sync_prepare_key_change', { masterPassword: 'fictional master password' })
    expect(get(sync).preparedRecoveryKit).toBe('FICTIONAL-KIT')
    await sync.rotateVaultKey('fictional master password')
    expect(core.invoke).toHaveBeenCalledWith('sync_rotate_vault_key', { masterPassword: 'fictional master password' })
    expect(get(sync).preparedRecoveryKit).toBe('')
    expect(get(sync).removalRecoveryKit).toBe('')
  })

  it('keeps no kit when preparing fails, when the person cancels, or when the change fails', async () => {
    answer({ sync_prepare_key_change: new Error('That master password is not correct.') })
    const sync = createSyncController()
    await sync.prepareKeyChange('wrong')
    expect(get(sync).preparedRecoveryKit).toBe('')
    expect(get(sync).loadError).toBe('That master password is not correct.')

    answer({ sync_prepare_key_change: { recoveryKit: 'FICTIONAL-KIT' }, sync_cancel_key_change: {} })
    await sync.prepareKeyChange('right')
    expect(get(sync).preparedRecoveryKit).toBe('FICTIONAL-KIT')
    await sync.cancelKeyChange()
    expect(get(sync).preparedRecoveryKit).toBe('')
    expect(core.invoke).toHaveBeenCalledWith('sync_cancel_key_change')

    answer({ sync_prepare_key_change: { recoveryKit: 'FICTIONAL-KIT' }, sync_remove_device: new Error('Show and save the new recovery kit first.') })
    await sync.prepareKeyChange('right')
    await sync.removeDevice('d2', 'right')
    expect(get(sync).preparedRecoveryKit).toBe('')
    expect(get(sync).loadError).toBe('Show and save the new recovery kit first.')
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

  it('keeps when Sesame last confirmed the minimum Sync version and says so plainly when it never has', async () => {
    answer({ sync_status: status({ floorConfirmedAt: 1_800_000_000 }), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.refresh()
    expect(get(sync).floorCheckedAt).toBe(1_800_000_000)
    answer({ sync_status: status(), sync_coordinator_status: idle })
    await sync.refresh()
    expect(get(sync).floorCheckedAt).toBe(0)
    expect(describeFloorCheck('approved', 0)).toBe('Sesame has not yet checked the minimum Sync version. It checks when it looks for an update.')
    expect(describeFloorCheck('approved', 1_800_000_000)).toMatch(/^Sesame last checked the minimum Sync version on .+\.$/)
    expect(describeFloorCheck('not_enrolled', 0)).toBe('')
    expect(describeFloorCheck('joining', 1_800_000_000)).toBe('')
  })

  it('tells the person what to do when the Sync version file is damaged and keeps the old version message for a real old build', () => {
    const state = (halt: string) => ({ phase: 'halted', halt, consecutiveFailures: 0, lastSuccessRevision: 0 })
    const damaged = describeCoordinatorState(state('floor_damaged'))
    expect(damaged).toContain('Sync version file')
    for (const name of ['sync-floor.json', 'sync-floor.json.tag', 'sync-floor.json.next']) expect(damaged).toContain(name)
    expect(describeCoordinatorState(state('incompatible'))).toBe('Sesame Sync needs a newer version of this app.')
  })

  it('keeps the note that peer checks were skipped until a sync completes them', async () => {
    answer({ sync_status: status({ peerChecksSkipped: true }), sync_coordinator_status: idle })
    const sync = createSyncController()
    await sync.refresh()
    expect(get(sync).peerChecksSkipped).toBe(true)
    answer({ sync_status: status({ peerChecksSkipped: false }), sync_coordinator_status: idle })
    await sync.refresh()
    expect(get(sync).peerChecksSkipped).toBe(false)
    answer({ sync_status: status(), sync_coordinator_status: idle })
    await sync.refresh()
    expect(get(sync).peerChecksSkipped).toBe(false)
  })

  it('tells the person when resolving a conflict removed older recovery copies', async () => {
    const side = { deviceLabel: 'Laptop', revision: 3, entryCount: 4, changedAt: '' }
    const conflict = { ...idle, phase: 'halted', halt: 'conflict', conflictRevision: 4 }
    answer({ sync_status: status(), sync_now: conflict, sync_conflict_details: { thisDevice: side, otherDevice: side } })
    const sync = approved()
    await sync.autoSync()
    await vi.waitFor(() => expect(get(sync).conflictDetailsLoaded).toBe(true))

    answer({ sync_status: status(), sync_coordinator_status: idle, sync_resolve_conflict: { recoveryCopies: ['a.sesame', 'b.sesame'], removedOldCopies: 2 } })
    await sync.resolveConflict('this')
    expect(get(sync).lastTransfer).toBe('Resolved. A recovery copy of each vault is saved on this device. Sesame removed 2 older recovery copies to stay within its limit.')
  })

  it('says nothing about removed copies when none were removed', async () => {
    const side = { deviceLabel: 'Laptop', revision: 3, entryCount: 4, changedAt: '' }
    const conflict = { ...idle, phase: 'halted', halt: 'conflict', conflictRevision: 4 }
    answer({ sync_status: status(), sync_now: conflict, sync_conflict_details: { thisDevice: side, otherDevice: side } })
    const sync = approved()
    await sync.autoSync()
    await vi.waitFor(() => expect(get(sync).conflictDetailsLoaded).toBe(true))

    answer({ sync_status: status(), sync_coordinator_status: idle, sync_resolve_conflict: { recoveryCopies: ['a.sesame', 'b.sesame'], removedOldCopies: 0 } })
    await sync.resolveConflict('other')
    expect(get(sync).lastTransfer).toBe('Resolved. A recovery copy of each vault is saved on this device.')
  })

  it('waits longer after each failed run and caps the wait', () => {
    expect(autoSyncBackoffMs(0)).toBe(0)
    expect(autoSyncBackoffMs(1)).toBe(60_000)
    expect(autoSyncBackoffMs(2)).toBe(120_000)
    expect(autoSyncBackoffMs(3)).toBe(240_000)
    expect(autoSyncBackoffMs(6)).toBe(30 * 60_000)
    expect(autoSyncBackoffMs(50)).toBe(30 * 60_000)
  })

  it('does not run a scheduled sync again before the backoff has passed, and runs it after', async () => {
    vi.useFakeTimers()
    const failing = { ...idle, phase: 'retrying', consecutiveFailures: 3 }
    answer({ sync_now: failing })
    const sync = approved()
    await sync.autoSync()
    const runs = () => core.invoke.mock.calls.filter((call) => call[0] === 'sync_now').length
    expect(runs()).toBe(1)

    await vi.advanceTimersByTimeAsync(60_000)
    await sync.autoSync()
    expect(runs()).toBe(1)

    await vi.advanceTimersByTimeAsync(180_000)
    await sync.autoSync()
    expect(runs()).toBe(2)
  })

  it('tries again at once when the network comes back, even inside the backoff', async () => {
    vi.useFakeTimers()
    answer({ sync_local_status: { state: 'approved', revision: 2, unsynced: false }, sync_now: { ...idle, phase: 'retrying', consecutiveFailures: 4 } })
    const sync = approved()
    const stop = sync.startBackground()
    await vi.advanceTimersByTimeAsync(10)
    const runs = () => core.invoke.mock.calls.filter((call) => call[0] === 'sync_now').length
    const before = runs()

    window.dispatchEvent(new Event('online'))
    await vi.advanceTimersByTimeAsync(10)

    expect(runs()).toBe(before + 1)
    stop()
  })

  it('shows a run that gave up as failing and never as synced', async () => {
    answer({ sync_now: { ...idle, phase: 'gave_up', consecutiveFailures: 6 } })
    const failing = approved()
    await failing.autoSync()
    expect(get(failing).activity).toBe('failing')
    expect(get(failing).lastSyncedAt).toBe(0)
    expect(describeSyncForChrome({ enrolled: true, state: 'approved', activity: 'failing', alarm: '', needsNewKey: false })).toEqual({ label: 'Synced vault · Could not sync, will retry', tone: 'warn' })
  })

  it('does not call a paused run synced because the vault was locked', async () => {
    answer({ sync_now: { ...idle, phase: 'paused', halt: 'locked' } })
    const paused = approved()
    await paused.autoSync()
    expect(get(paused).activity).toBe('idle')
    expect(get(paused).lastSyncedAt).toBe(0)
  })

  it('stamps the last sync time only when a run ended idle', async () => {
    answer({ sync_now: idle })
    const synced = approved()
    await synced.autoSync()
    expect(get(synced).activity).toBe('synced')
    expect(get(synced).lastSyncedAt).toBeGreaterThan(0)
  })

  it('tells the host that Sync now was pressed by a person and that a scheduled run was not', async () => {
    answer({ sync_status: status(), sync_coordinator_status: idle, sync_now: idle })
    const sync = approved()
    await sync.autoSync()
    expect(core.invoke).toHaveBeenCalledWith('sync_now')
    core.invoke.mockClear()
    await sync.syncNow()
    expect(core.invoke).toHaveBeenCalledWith('sync_now', { manual: true })
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

describe('showing what another device changed', () => {
  const approved = () => {
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: true, state: 'approved' }))
    return createSyncController()
  }

  beforeEach(() => {
    core.invoke.mockReset()
    localStorage.clear()
  })

  it('tells the app once when a background sync applied a change, and not when it only checked', async () => {
    const sync = approved()
    const applied = vi.fn()
    sync.onVaultApplied(applied)
    answer({ sync_now: idle })
    await sync.autoSync()
    expect(applied).not.toHaveBeenCalled()
    answer({ sync_now: { ...idle, downloadsApplied: 1 } })
    await sync.autoSync()
    expect(applied).toHaveBeenCalledTimes(1)
    await sync.autoSync()
    expect(applied).toHaveBeenCalledTimes(1)
    answer({ sync_now: { ...idle, downloadsApplied: 2 } })
    await sync.autoSync()
    expect(applied).toHaveBeenCalledTimes(2)
  })

  it('tells the app when Sync now applied a change', async () => {
    const sync = approved()
    const applied = vi.fn()
    sync.onVaultApplied(applied)
    answer({ sync_now: { ...idle, downloadsApplied: 1 }, sync_status: status(), sync_coordinator_status: { ...idle, downloadsApplied: 1 } })
    await sync.syncNow()
    expect(applied).toHaveBeenCalledTimes(1)
  })

  it('tells the app after a manual download and after joining a synced vault', async () => {
    const sync = approved()
    const applied = vi.fn()
    sync.onVaultApplied(applied)
    answer({
      sync_download_vault: { revision: 4, vaultEpoch: 1, entryCount: 2 },
      sync_join_with_code: { recoveryKit: '' },
      sync_status: status(),
      sync_coordinator_status: idle,
    })
    await sync.pull()
    expect(applied).toHaveBeenCalledTimes(1)
    await sync.join('ABCD-EFGH', 'Fictional laptop', 'fictional master password')
    expect(applied).toHaveBeenCalledTimes(2)
  })

  it('tells the app when a status read shows a change it had not been told about', async () => {
    const sync = approved()
    const applied = vi.fn()
    sync.onVaultApplied(applied)
    answer({ sync_status: status(), sync_coordinator_status: { ...idle, downloadsApplied: 2 } })
    await sync.refresh()
    expect(applied).toHaveBeenCalledTimes(1)
    await sync.refresh()
    expect(applied).toHaveBeenCalledTimes(1)
  })

  it('tells the app when a conflict is settled by keeping the other device, and not when this one is kept', async () => {
    const side = { deviceLabel: 'Laptop', revision: 3, changedAt: '', entryCount: 1 }
    const conflicted = { ...idle, phase: 'halted', halt: 'conflict', conflictRevision: 4 }
    answer({ sync_now: conflicted, sync_conflict_details: { thisDevice: side, otherDevice: side } })
    const sync = approved()
    const applied = vi.fn()
    sync.onVaultApplied(applied)
    await sync.autoSync()
    answer({ sync_resolve_conflict: { recoveryCopies: [] }, sync_status: status(), sync_coordinator_status: idle })
    await sync.resolveConflict('this')
    expect(applied).not.toHaveBeenCalled()
    await sync.resolveConflict('other')
    expect(applied).toHaveBeenCalledTimes(1)
  })

  it('does not tell the app about a failed download', async () => {
    const sync = approved()
    const applied = vi.fn()
    sync.onVaultApplied(applied)
    answer({ sync_download_vault: new Error('This device has changes that are not synced yet.') })
    await sync.pull()
    expect(applied).not.toHaveBeenCalled()
  })

  it('stops telling a listener that was removed', async () => {
    const sync = approved()
    const applied = vi.fn()
    const stop = sync.onVaultApplied(applied)
    stop()
    answer({ sync_now: { ...idle, downloadsApplied: 1 } })
    await sync.autoSync()
    expect(applied).not.toHaveBeenCalled()
  })
})

describe('a device that is waiting for the new vault key', () => {
  beforeEach(() => {
    core.invoke.mockReset()
    localStorage.clear()
  })

  const waiting = { ...idle, phase: 'halted', halt: 'needs_new_key' }

  it('says the device needs the new key and never says it could not reach the service', () => {
    const text = describeCoordinatorState({ ...waiting, consecutiveFailures: 0, lastSuccessRevision: 3 })
    expect(text).toBe('This device needs the new vault key. Open Sync and take it.')
    expect(text).not.toContain('reach')
  })

  it('shows the bar as needing the new key as soon as a run is refused for it, before the panel is opened', async () => {
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: true, state: 'approved' }))
    answer({ sync_now: waiting })
    const sync = createSyncController()
    await sync.autoSync()
    expect(get(sync).needsNewKey).toBe(true)
    expect(describeSyncForChrome(get(sync))).toEqual({ label: 'Synced vault · Needs the new key', tone: 'warn' })
  })

  it('stops asking the service while it waits and clears the wait once the key is taken', async () => {
    localStorage.setItem('sesame-sync-cache-v1', JSON.stringify({ enrolled: true, state: 'approved' }))
    answer({ sync_now: waiting })
    const sync = createSyncController()
    await sync.autoSync()
    core.invoke.mockClear()
    await sync.autoSync()
    expect(core.invoke).not.toHaveBeenCalled()
    answer({ sync_take_new_key: { recoveryKit: '' }, sync_status: status({ needsNewKey: false }), sync_coordinator_status: idle })
    await sync.takeNewKey('fictional master password')
    expect(get(sync).needsNewKey).toBe(false)
    expect(get(sync).coordinator.phase).toBe('idle')
  })
})

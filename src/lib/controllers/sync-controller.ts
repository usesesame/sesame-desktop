import { invoke } from '@tauri-apps/api/core'
import type { SyncConflictSide } from '../types'
import { controllerStore } from './controller-store'

export type SyncActivity = 'idle' | 'pending' | 'syncing' | 'synced' | 'offline' | 'failing' | 'attention'

export interface SyncControllerState {
  activity: SyncActivity
  lastSyncedAt: number
  enableOpen: boolean
  pairingOpen: boolean
  joinOpen: boolean
  conflictOpen: boolean
  working: boolean
  error: string
  loadError: string
  lastTransfer: string
  enrolled: boolean
  state: string
  needsNewKey: boolean
  alarm: string
  confirmedAt: number
  peerChecksSkipped: boolean
  devices: SyncDeviceView[]
  pairingCode: string
  pairingSecondsLeft: number
  pairingPhase: 'idle' | 'waiting' | 'done'
  pairingDone: string
  conflictDetailsLoaded: boolean
  conflictDetailsError: string
  coordinator: SyncCoordinatorView
  backups: SyncBackupView[]
  removalRecoveryKit: string
  conflictThisDevice: SyncConflictSide
  conflictOtherDevice: SyncConflictSide
}

export interface SyncCoordinatorView {
  phase: string
  halt: string
  conflictRevision: number
  pending: boolean
  lastSuccessRevision: number
  consecutiveFailures: number
}

export interface SyncBackupView {
  name: string
  side: string
  revision: number
  entryCount: number
  createdAt: string
}

export interface SyncDeviceView {
  deviceId: string
  label: string
  state: string
  isThisDevice: boolean
  addedIndex: number
}

interface SyncTransferResult {
  revision: number
  vaultEpoch: number
  entryCount: number
}

function describe(action: string, result: SyncTransferResult): string {
  const entries = `${result.entryCount} ${result.entryCount === 1 ? 'login' : 'logins'}`
  return `${action} at revision ${result.revision}, ${entries}.`
}

interface SyncStatusView {
  enrolled: boolean
  state: string
  vaultEpoch: number
  revision: number
  devices: SyncDeviceView[]
  needsNewKey: boolean
  alarm: string | null
  confirmedAt: number | null
  floorConfirmedAt?: number | null
  peerChecksSkipped?: boolean
}

const emptySide: SyncConflictSide = {
  deviceLabel: '',
  revision: 0,
  changedAt: '',
  entryCount: 0,
}

const initialState: SyncControllerState = {
  activity: 'idle',
  lastSyncedAt: 0,
  enableOpen: false,
  pairingOpen: false,
  joinOpen: false,
  conflictOpen: false,
  working: false,
  error: '',
  loadError: '',
  lastTransfer: '',
  enrolled: false,
  state: 'not_enrolled',
  needsNewKey: false,
  alarm: '',
  confirmedAt: 0,
  floorCheckedAt: 0,
  peerChecksSkipped: false,
  devices: [],
  pairingCode: '',
  pairingSecondsLeft: 0,
  pairingPhase: 'idle',
  pairingDone: '',
  coordinator: {
    phase: 'idle',
    halt: '',
    conflictRevision: 0,
    pending: false,
    lastSuccessRevision: 0,
    consecutiveFailures: 0,
  },
  backups: [],
  removalRecoveryKit: '',
  conflictDetailsLoaded: false,
  conflictDetailsError: '',
  conflictThisDevice: emptySide,
  conflictOtherDevice: emptySide,
}

const CACHE_KEY = 'sesame-sync-cache-v1'
const BACKGROUND_INTERVAL_MS = 5 * 60 * 1000
const BACKOFF_FIRST_MS = 60 * 1000
const BACKOFF_MAX_MS = 30 * 60 * 1000

export function autoSyncBackoffMs(failures: number): number {
  if (failures <= 0) return 0
  return Math.min(BACKOFF_FIRST_MS * 2 ** (failures - 1), BACKOFF_MAX_MS)
}
const CHANGE_DELAY_MS = 600

function readCache(): Pick<SyncControllerState, 'enrolled' | 'state'> | null {
  try {
    const raw = window.localStorage.getItem(CACHE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as { enrolled?: unknown; state?: unknown }
    if (typeof parsed.enrolled !== 'boolean' || typeof parsed.state !== 'string') return null
    return { enrolled: parsed.enrolled, state: parsed.state }
  } catch {
    return null
  }
}

function writeCache(enrolled: boolean, state: string) {
  try {
    window.localStorage.setItem(CACHE_KEY, JSON.stringify({ enrolled, state }))
  } catch {
    return
  }
}

const ENTITLEMENT_PREFIX = 'sync_not_entitled:'

function readableMessage(error: unknown, fallback: string) {
  const message = typeof error === 'string' ? error : fallback
  return message.startsWith(ENTITLEMENT_PREFIX) ? message.slice(ENTITLEMENT_PREFIX.length) : message
}

export type SyncChromeTone = 'ok' | 'busy' | 'warn'

export function describeFloorCheck(state: string, floorCheckedAt: number): string {
  if (state !== 'approved') return ''
  if (floorCheckedAt === 0) return 'Sesame has not yet checked the minimum Sync version.'
  return `Sesame last checked the minimum Sync version on ${new Date(floorCheckedAt * 1000).toLocaleString()}.`
}

export function describeSyncForChrome(state: Pick<SyncControllerState, 'enrolled' | 'state' | 'activity' | 'alarm' | 'needsNewKey'>): { label: string; tone: SyncChromeTone } | undefined {
  if (!state.enrolled || state.state !== 'approved') return undefined
  if (state.alarm) return { label: 'Synced vault · Devices disagree, sync paused', tone: 'warn' }
  if (state.needsNewKey) return { label: 'Synced vault · Needs the new key', tone: 'warn' }
  switch (state.activity) {
    case 'pending':
      return { label: 'Synced vault · Changes not synced yet', tone: 'busy' }
    case 'syncing':
      return { label: 'Synced vault · Syncing…', tone: 'busy' }
    case 'offline':
      return { label: 'Synced vault · Offline, will retry', tone: 'warn' }
    case 'failing':
      return { label: 'Synced vault · Could not sync, will retry', tone: 'warn' }
    case 'attention':
      return { label: 'Synced vault · Needs attention', tone: 'warn' }
    case 'synced':
      return { label: 'Synced vault · Up to date', tone: 'ok' }
    default:
      return { label: 'Synced vault', tone: 'ok' }
  }
}

export function createSyncController() {
  const store = controllerStore({ ...initialState, ...(readCache() ?? {}) })

  function fail(error: unknown) {
    const message = typeof error === 'string' ? error : 'Sesame Sync could not complete that.'
    if (message.startsWith('sync_conflict:')) {
      const revision = Number.parseInt(message.slice('sync_conflict:'.length), 10)
      store.patch({
        working: false,
        error: '',
        conflictOpen: true,
        conflictOtherDevice: {
          ...emptySide,
          deviceLabel: 'Another device',
          revision: Number.isFinite(revision) ? revision : 0,
        },
      })
      store.patch({ conflictDetailsLoaded: false, conflictDetailsError: '' })
      void loadConflictDetails()
      return
    }
    const forkPrefix = 'sync_fork:'
    if (message.startsWith(forkPrefix)) {
      store.patch({ working: false, error: '', alarm: message.slice(forkPrefix.length) })
      return
    }
    const entitlementPrefix = 'sync_not_entitled:'
    store.patch({ working: false, error: message.startsWith(entitlementPrefix) ? message.slice(entitlementPrefix.length) : message })
  }

  async function loadConflictDetails() {
    try {
      const detail = await invoke<{
        thisDevice: SyncConflictSide
        otherDevice: SyncConflictSide
      }>('sync_conflict_details')
      store.patch({
        conflictThisDevice: detail.thisDevice,
        conflictOtherDevice: detail.otherDevice,
        conflictDetailsLoaded: true,
      })
    } catch {
      store.patch({
        conflictDetailsLoaded: false,
        conflictDetailsError:
          'Sesame could not read both versions. Check your connection and open this again.',
      })
    }
  }

  async function loadCoordinator() {
    try {
      const coordinator = await invoke<SyncCoordinatorView>('sync_coordinator_status')
      store.patch({ coordinator })
    } catch {
      // The panel keeps its last known state rather than claiming idle.
    }
  }

  async function loadLocal() {
    try {
      const local = await invoke<{ state: string; revision: number; unsynced?: boolean }>('sync_local_status')
      const enrolled = local.state !== 'not_enrolled'
      const { activity } = store.value()
      const unsynced = local.state === 'approved' && local.unsynced === true
      store.patch({
        enrolled,
        state: local.state,
        activity: unsynced && activity !== 'syncing' ? 'pending' : activity === 'pending' && !unsynced ? 'synced' : activity,
      })
      writeCache(enrolled, local.state)
    } catch {
      return
    }
  }

  async function refresh() {
    store.patch({ working: true })
    try {
      const status = await invoke<SyncStatusView>('sync_status')
      writeCache(status.enrolled, status.state)
      store.patch({
        enrolled: status.enrolled,
        state: status.state,
        needsNewKey: status.needsNewKey,
        alarm: status.alarm ?? '',
        confirmedAt: status.confirmedAt ?? 0,
        floorCheckedAt: status.floorConfirmedAt ?? 0,
        peerChecksSkipped: status.peerChecksSkipped ?? false,
        devices: status.devices,
        error: '',
        working: false,
        loadError: '',
      })
      await loadCoordinator()
    } catch (error) {
      store.patch({
        working: false,
        loadError:
          readableMessage(error, 'Sesame could not read the Sync status.'),
      })
    }
  }

  let countdown: ReturnType<typeof setInterval> | undefined
  let changeTimer: ReturnType<typeof setTimeout> | undefined
  let rerun = false
  let lastAutoAttemptAt = 0

  function activityFor(status: SyncCoordinatorView): SyncActivity {
    switch (status.phase) {
      case 'working':
        return 'syncing'
      case 'retrying':
        return 'offline'
      case 'gave_up':
        return 'failing'
      case 'paused':
        return 'idle'
      case 'halted':
        return 'attention'
      default:
        return 'synced'
    }
  }

  function stopCountdown() {
    if (countdown !== undefined) {
      clearInterval(countdown)
      countdown = undefined
    }
  }

  const api = {
    subscribe: store.subscribe,
    refresh,
    openEnable() {
      store.patch({ enableOpen: true, error: '' })
    },
    closeEnable() {
      store.patch({ enableOpen: false, error: '' })
    },
    async enable(label: string) {
      store.patch({ working: true, error: '' })
      try {
        await invoke('sync_create_vault', { label })
        store.patch({ working: false, enableOpen: false, lastTransfer: 'Sync is on for this vault.' })
        await refresh()
        await this.push()
      } catch (error) {
        fail(error)
      }
    },
    openJoin() {
      store.patch({ joinOpen: true, error: '' })
    },
    closeJoin() {
      store.patch({ joinOpen: false, error: '' })
    },
    async join(code: string, label: string, masterPassword: string) {
      store.patch({ working: true, error: '' })
      try {
        const result = await invoke<{ recoveryKit: string }>('sync_join_with_code', {
          code,
          label,
          masterPassword,
        })
        store.patch({
          working: false,
          joinOpen: false,
          removalRecoveryKit: result.recoveryKit,
          lastTransfer: 'This device joined the synced vault.',
        })
        await refresh()
      } catch (error) {
        await refresh()
        fail(error)
      }
    },
    async openPairing() {
      store.patch({ pairingOpen: true, error: '', pairingDone: '', pairingPhase: 'idle', pairingCode: '' })
      try {
        const shown = await invoke<{ code: string; expiresInSeconds: number }>('sync_pairing_code')
        const deadline = Date.now() + shown.expiresInSeconds * 1000
        store.patch({
          pairingCode: shown.code,
          pairingPhase: 'waiting',
          pairingSecondsLeft: shown.expiresInSeconds,
        })
        stopCountdown()
        countdown = setInterval(() => {
          store.patch({ pairingSecondsLeft: Math.max(0, Math.round((deadline - Date.now()) / 1000)) })
        }, 1000)
        const approved = await invoke<{ label: string }>('sync_approve_with_code')
        stopCountdown()
        store.patch({ pairingPhase: 'done', pairingDone: approved.label, pairingCode: '' })
        await refresh()
      } catch (error) {
        stopCountdown()
        store.patch({
          pairingPhase: 'idle',
          pairingCode: '',
          error: typeof error === 'string' ? error : 'Sesame could not add that device.',
        })
      }
    },
    async closePairing() {
      stopCountdown()
      await invoke('sync_cancel_pairing').catch(() => undefined)
      store.patch({ pairingOpen: false, pairingPhase: 'idle', pairingCode: '', error: '' })
    },
    async takeNewKey(masterPassword: string) {
      store.patch({ working: true, error: '' })
      try {
        const result = await invoke<{ recoveryKit: string }>('sync_take_new_key', {
          masterPassword,
        })
        store.patch({
          working: false,
          removalRecoveryKit: result.recoveryKit,
          lastTransfer: 'This device has the new vault key.',
        })
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
    async leave(masterPassword: string, force: boolean) {
      store.patch({ working: true, loadError: '' })
      try {
        await invoke('sync_disable', { masterPassword, force })
        store.patch({ working: false, lastTransfer: 'This device left Sync. Your local vault is untouched.' })
        await refresh()
      } catch (error) {
        store.patch({
          working: false,
          loadError: typeof error === 'string' ? error : 'Sesame could not turn Sync off.',
        })
      }
    },
    async removeDevice(deviceId: string, masterPassword: string) {
      store.patch({ working: true, loadError: '' })
      try {
        const result = await invoke<{ recoveryKit: string }>('sync_remove_device', {
          deviceId,
          masterPassword,
        })
        store.patch({
          working: false,
          removalRecoveryKit: result.recoveryKit,
          lastTransfer: 'Device removed. Your vault now uses a new key.',
        })
        await refresh()
      } catch (error) {
        store.patch({
          working: false,
          loadError:
            readableMessage(error, 'Sesame could not remove that device.'),
        })
      }
    },
    /// Clears the recovery kit from memory once it has been written down.
    dismissRecoveryKit() {
      store.patch({ removalRecoveryKit: '' })
    },
    loadLocal,
    async autoSync() {
      const current = store.value()
      const halted = current.coordinator.phase === 'halted'
      if (current.activity === 'syncing') {
        rerun = true
        return
      }
      if (current.working || current.state !== 'approved' || current.needsNewKey || halted || current.alarm) {
        return
      }
      const wait = autoSyncBackoffMs(current.coordinator.consecutiveFailures)
      if (wait > 0 && Date.now() - lastAutoAttemptAt < wait) return
      lastAutoAttemptAt = Date.now()
      store.patch({ activity: 'syncing' })
      try {
        const status = await invoke<SyncCoordinatorView>('sync_now')
        store.patch({ coordinator: status, activity: activityFor(status), lastSyncedAt: status.phase === 'idle' ? Date.now() : store.value().lastSyncedAt })
        if (status.halt === 'conflict') {
          store.patch({
            conflictOpen: true,
            conflictDetailsLoaded: false,
            conflictDetailsError: '',
            conflictOtherDevice: {
              ...emptySide,
              deviceLabel: 'Another device',
              revision: status.conflictRevision,
            },
          })
          void loadConflictDetails()
        }
      } catch {
        store.patch({ working: false, activity: 'offline' })
      } finally {
        if (rerun) {
          rerun = false
          void api.autoSync()
        }
      }
    },
    startBackground() {
      void loadLocal().then(() => api.autoSync())
      const timer = setInterval(() => void api.autoSync(), BACKGROUND_INTERVAL_MS)
      const onFocus = () => void api.autoSync()
      const onOnline = () => {
        lastAutoAttemptAt = 0
        void api.autoSync()
      }
      window.addEventListener('focus', onFocus)
      window.addEventListener('online', onOnline)
      return () => {
        clearInterval(timer)
        window.removeEventListener('focus', onFocus)
        window.removeEventListener('online', onOnline)
        if (changeTimer !== undefined) clearTimeout(changeTimer)
        changeTimer = undefined
      }
    },
    vaultChanged() {
      if (store.value().state !== 'approved') return
      void loadLocal()
      if (changeTimer !== undefined) clearTimeout(changeTimer)
      changeTimer = setTimeout(() => {
        changeTimer = undefined
        void api.autoSync()
      }, CHANGE_DELAY_MS)
    },
    async syncNow() {
      store.patch({ working: true, error: '' })
      try {
        const status = await invoke<SyncCoordinatorView>('sync_now', { manual: true })
        store.patch({ working: false, coordinator: status })
        if (status.halt === 'conflict') {
          store.patch({
            conflictOpen: true,
            conflictDetailsLoaded: false,
            conflictDetailsError: '',
            conflictOtherDevice: {
              ...emptySide,
              deviceLabel: 'Another device',
              revision: status.conflictRevision,
            },
          })
          void loadConflictDetails()
          return
        }
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
    async loadBackups() {
      try {
        const backups = await invoke<SyncBackupView[]>('sync_list_conflict_backups')
        store.patch({ backups })
      } catch {
        store.patch({ backups: [] })
      }
    },
    async restoreBackup(name: string) {
      store.patch({ working: true, loadError: '' })
      try {
        await invoke('sync_restore_conflict_backup', { name })
        store.patch({
          working: false,
          lastTransfer: 'Recovery copy restored. Set Sesame Sync up again to keep syncing.',
        })
        await refresh()
      } catch (error) {
        store.patch({
          working: false,
          loadError:
            readableMessage(error, 'Sesame could not restore that copy.'),
        })
      }
    },
    async resetVault() {
      store.patch({ working: true, loadError: '' })
      try {
        await invoke('sync_reset_vault')
        store.patch({ working: false, lastTransfer: 'Sesame Sync was reset for this account.' })
        await refresh()
      } catch (error) {
        store.patch({
          working: false,
          loadError:
            readableMessage(error, 'Sesame could not reset Sesame Sync.'),
        })
      }
    },
    closeConflict() {
      store.patch({ conflictOpen: false, error: '', conflictDetailsError: '' })
    },
    async resolveConflict(choice: 'this' | 'other') {
      if (!store.value().conflictDetailsLoaded) {
        return
      }
      store.patch({ working: true, error: '' })
      try {
        const result = await invoke<{ recoveryCopies: string[]; removedOldCopies?: number }>('sync_resolve_conflict', {
          keep: choice,
        })
        const removed = result.removedOldCopies ?? 0
        const base =
          result.recoveryCopies.length === 2
            ? 'Resolved. A recovery copy of each vault is saved on this device.'
            : 'Resolved.'
        store.patch({
          working: false,
          conflictOpen: false,
          lastTransfer: removed > 0 ? `${base} Sesame removed ${removed} older recovery ${removed === 1 ? 'copy' : 'copies'} to stay within its limit.` : base,
        })
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
    async push() {
      store.patch({ working: true, error: '', loadError: '' })
      try {
        const result = await invoke<SyncTransferResult>('sync_upload_vault')
        store.patch({ working: false, lastTransfer: describe('Uploaded', result) })
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
    /// Replaces the local vault after Rust verifies the envelope against the sending device's key.
    async pull() {
      store.patch({ working: true, error: '', loadError: '' })
      try {
        const result = await invoke<SyncTransferResult>('sync_download_vault')
        store.patch({ working: false, lastTransfer: describe('Updated from Sync', result) })
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
  }
  return api
}

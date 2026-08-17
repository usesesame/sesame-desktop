import { invoke } from '@tauri-apps/api/core'
import type { SyncConflictSide } from '../types'
import { controllerStore } from './controller-store'

/// Sync preview screens. Never handles a key, sealed package, or vault content.

export interface SyncPreviewState {
  enableOpen: boolean
  approveOpen: boolean
  conflictOpen: boolean
  working: boolean
  error: string
  loadError: string
  lastTransfer: string
  enrolled: boolean
  state: string
  devices: SyncDeviceView[]
  pendingDeviceId: string
  pendingLabel: string
  pendingFingerprint: string
  pendingHandle: string
  ownFingerprint: string
  pendingRequestedAt: string
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
  /// Derived in Rust; the webview must never compute one.
  fingerprint: string
  state: string
  label: string
  createdAt: string
  approvedAt?: string
  revokedAt?: string
  isThisDevice: boolean
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
  devices: SyncDeviceView[]
}

const emptySide: SyncConflictSide = {
  deviceLabel: '',
  revision: 0,
  changedAt: '',
  entryCount: 0,
}

const initialState: SyncPreviewState = {
  enableOpen: false,
  approveOpen: false,
  conflictOpen: false,
  working: false,
  error: '',
  loadError: '',
  lastTransfer: '',
  enrolled: false,
  state: 'not_enrolled',
  devices: [],
  pendingDeviceId: '',
  pendingLabel: '',
  pendingFingerprint: '',
  pendingHandle: '',
  ownFingerprint: '',
  pendingRequestedAt: '',
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

export function createSyncPreviewController() {
  const store = controllerStore(initialState)

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
    store.patch({ working: false, error: message })
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

  async function prepareApproval(deviceId: string) {
    try {
      const prepared = await invoke<{ handle: string; fingerprint: string; label: string }>(
        'sync_prepare_approval',
        { deviceId },
      )
      store.patch({
        pendingHandle: prepared.handle,
        pendingFingerprint: prepared.fingerprint,
        pendingLabel: prepared.label,
      })
    } catch {
      // A fingerprint that was not frozen must not be confirmed.
      store.patch({ pendingHandle: '', pendingFingerprint: '' })
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

  async function loadOwnFingerprint() {
    try {
      const fingerprint = await invoke<string>('sync_this_device_fingerprint')
      store.patch({ ownFingerprint: fingerprint })
    } catch {
      store.patch({ ownFingerprint: '' })
    }
  }

  async function refresh() {
    store.patch({ working: true })
    try {
      const status = await invoke<SyncStatusView>('sync_status')
      const pending = status.devices.find(
        (device) => device.state === 'pending' && !device.isThisDevice,
      )
      const own = status.devices.find((device) => device.isThisDevice)
      store.patch({
        enrolled: status.enrolled,
        state: own?.state ?? (status.enrolled ? status.state : 'not_enrolled'),
        devices: status.devices,
        error: '',
        pendingDeviceId: pending?.deviceId ?? '',
        pendingLabel: pending?.label ?? '',
        pendingFingerprint: '',
        pendingHandle: '',
        pendingRequestedAt: pending?.createdAt ?? '',
        approveOpen: Boolean(pending),
        working: false,
        loadError: '',
      })
      // Approval seals to the keys Rust froze, not ones a later response could contradict.
      if (pending) {
        await prepareApproval(pending.deviceId)
      }
      if (own?.state === 'pending') {
        await loadOwnFingerprint()
      }
      await loadCoordinator()
    } catch (error) {
      store.patch({
        working: false,
        loadError:
          typeof error === 'string' ? error : 'Sesame could not read the Sync status.',
      })
    }
  }

  return {
    subscribe: store.subscribe,
    refresh,
    openEnable() {
      store.patch({ enableOpen: true, error: '' })
    },
    closeEnable() {
      store.patch({ enableOpen: false, error: '' })
    },
    async enable() {
      store.patch({ working: true, error: '' })
      try {
        await invoke('sync_enroll_device', { label: 'This device' })
        store.patch({ working: false, enableOpen: false })
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
    /// Approves the frozen keys via handle; naming a device id could serve a different key.
    async approveDevice() {
      const { pendingHandle } = store.value()
      if (!pendingHandle) {
        store.patch({ error: 'Sesame could not confirm that device. Try again.' })
        return
      }
      store.patch({ working: true, error: '' })
      try {
        await invoke('sync_approve_prepared_device', { handle: pendingHandle })
        store.patch({ working: false, approveOpen: false, pendingHandle: '' })
        await refresh()
      } catch (error) {
        fail(error)
      }
    },
    async denyDevice() {
      const { pendingDeviceId } = store.value()
      store.patch({ working: true, error: '' })
      try {
        await invoke('sync_deny_device', { deviceId: pendingDeviceId })
        store.patch({ working: false, approveOpen: false })
        await refresh()
      } catch (error) {
        fail(error)
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
            typeof error === 'string' ? error : 'Sesame could not remove that device.',
        })
      }
    },
    /// Clears the recovery kit from memory once it has been written down.
    dismissRecoveryKit() {
      store.patch({ removalRecoveryKit: '' })
    },
    async syncNow() {
      store.patch({ working: true, error: '' })
      try {
        const status = await invoke<SyncCoordinatorView>('sync_now')
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
            typeof error === 'string' ? error : 'Sesame could not restore that copy.',
        })
      }
    },
    async adoptVault(masterPassword: string) {
      store.patch({ working: true, error: '' })
      try {
        const result = await invoke<{ recoveryKit: string }>('sync_adopt_vault', {
          masterPassword,
        })
        store.patch({
          working: false,
          removalRecoveryKit: result.recoveryKit,
          lastTransfer: 'This device joined the synced vault.',
        })
        await refresh()
      } catch (error) {
        fail(error)
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
            typeof error === 'string' ? error : 'Sesame could not reset Sesame Sync.',
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
        const result = await invoke<{ recoveryCopies: string[] }>('sync_resolve_conflict', {
          keep: choice,
        })
        store.patch({
          working: false,
          conflictOpen: false,
          lastTransfer:
            result.recoveryCopies.length === 2
              ? 'Resolved. A recovery copy of each vault is saved on this device.'
              : 'Resolved.',
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
}

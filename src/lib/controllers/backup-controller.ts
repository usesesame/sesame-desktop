import type { AppStores } from '../stores/app-stores'
import type { BackupSelection, BackupVerification, RecoveryHealth, RestoreBackupResult } from '../types'
import {
  chooseBackupForRestore,
  createBackup,
  exportBackup,
  getRecoveryHealth,
  getVaultStatus,
  grantPresence,
  PRESENCE_REQUIRED,
  recordDiagnostic,
  restoreBackup,
  verifyBackup,
} from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface BackupControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  onRestored: (message: string) => void
}

export function createBackupController({ stores, feedback, modal, onRestored }: BackupControllerOptions) {
  const { selection, vault } = stores
  const state = controllerStore({
    restoreSelection: null as BackupSelection | null,
    restoreConfirmed: false,
    restoreSecret: '',
    restoringBackup: false,
    restorePresenceRequired: false,
    restorePresencePassword: '',
    drillSelection: null as BackupSelection | null,
    drillSecret: '',
    drillVerification: null as BackupVerification | null,
    drillWorking: false,
    drillRestoring: false,
    drillPresenceRequired: false,
    drillPresencePassword: '',
    drillError: '',
    health: null as RecoveryHealth | null,
    healthLoading: false,
    exportPresenceRequired: false,
    exportPresencePassword: '',
  })

  function clearDrill() {
    state.patch({
      drillSelection: null,
      drillSecret: '',
      drillVerification: null,
      drillWorking: false,
      drillRestoring: false,
      drillPresenceRequired: false,
      drillPresencePassword: '',
      drillError: '',
    })
  }

  function restoreRevisionCopy(restored: RestoreBackupResult): string {
    return restored.replacedRevision === undefined
      ? ''
      : ` The restored vault is at revision ${restored.restoredRevision}, replacing revision ${restored.replacedRevision}.`
  }

  async function applyRestoredVault(message: string) {
    vault.patch({ snapshot: null, loginCard: null, status: { ...(await getVaultStatus()), unlocked: false } })
    selection.patch({ activeItemId: null, activeItemKind: null, activeView: 'vault' })
    state.patch({ exportPresenceRequired: false, exportPresencePassword: '' })
    onRestored(message)
  }

  async function runRestore() {
    const current = state.value()
    if (!current.restoreSelection || !current.restoreSecret || current.restoringBackup) return
    if (vault.value().status.exists && !current.restoreConfirmed) return
    state.patch({ restoringBackup: true })
    feedback.clearError()
    try {
      const hadVault = vault.value().status.exists
      const upgraded = current.restoreSelection.compatibility === 'upgrade'
      const restored = await restoreBackup(current.restoreSelection.token, current.restoreSecret)
      const action = upgraded ? 'Older backup upgraded and restored.' : 'Backup restored.'
      const message = restored.safetyBackupName
        ? `${action} Sesame kept the previous vault as ${restored.safetyBackupName}.${restoreRevisionCopy(restored)}`
        : hadVault
          ? `${action}${restoreRevisionCopy(restored)}`
          : `${action} Unlock with the master password or recovery kit from that backup.`
      modal.close('restore')
      state.patch({ restoreSelection: null, restoreConfirmed: false, restoreSecret: '', restorePresenceRequired: false, restorePresencePassword: '' })
      await applyRestoredVault(message)
    } catch (error) {
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) {
        state.patch({ restorePresenceRequired: true, restorePresencePassword: '' })
        feedback.setErrorMessage('Confirm your current master password before Sesame replaces the vault.')
      } else {
        feedback.setError(error)
      }
    } finally {
      state.patch({ restoringBackup: false })
    }
  }

  async function runDrillRestore() {
    const current = state.value()
    if (!current.drillSelection || !current.drillVerification || !current.drillSecret || current.drillRestoring) return
    state.patch({ drillRestoring: true, drillError: '', drillPresenceRequired: false })
    try {
      const upgraded = current.drillVerification.compatibility === 'upgrade'
      const restored = await restoreBackup(current.drillSelection.token, current.drillSecret)
      const action = upgraded
        ? 'Recovery drill complete. The older backup was upgraded and restored.'
        : 'Recovery drill complete. The verified backup was restored.'
      const message = restored.safetyBackupName
        ? `${action} Sesame kept the previous vault as ${restored.safetyBackupName}.${restoreRevisionCopy(restored)}`
        : `${action}${restoreRevisionCopy(restored)}`
      modal.close('backup-drill')
      clearDrill()
      await applyRestoredVault(message)
    } catch (error) {
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) {
        state.patch({ drillPresenceRequired: true })
      } else {
        state.patch({ drillError: error instanceof Error ? error.message : 'The verified backup could not be restored.' })
      }
    } finally {
      state.patch({ drillRestoring: false })
    }
  }

  async function refreshHealth() {
    if (state.value().healthLoading) return
    state.patch({ healthLoading: true })
    try {
      state.patch({ health: await getRecoveryHealth() })
    } catch {
      // Health is advisory; never block the UI.
    } finally {
      state.patch({ healthLoading: false })
    }
  }

  async function runEncryptedExport() {
    try {
      const name = await exportBackup()
      if (name) feedback.showNotice('Backup exported', `${name} is still encrypted.`)
      await refreshHealth()
      state.patch({ exportPresenceRequired: false, exportPresencePassword: '' })
    } catch (error) {
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) {
        state.patch({ exportPresenceRequired: true })
        feedback.setErrorMessage('Confirm your master password before Sesame writes a backup copy.')
      } else {
        feedback.setError(error)
      }
    }
  }

  return {
    state,
    refreshHealth,
    async makeBackup() {
      try {
        feedback.showNotice('Backup created', await createBackup())
        await refreshHealth()
      } catch (error) {
        feedback.setError(error)
      }
    },
    async exportEncryptedBackup() {
      await runEncryptedExport()
    },
    async confirmExportPresence() {
      const secret = state.value().exportPresencePassword
      if (!secret || state.value().healthLoading) return
      state.patch({ healthLoading: true })
      feedback.clearError()
      try {
        await grantPresence(secret)
        state.patch({ exportPresencePassword: '' })
        await runEncryptedExport()
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ healthLoading: false })
      }
    },
    async beginRestore() {
      feedback.clearError()
      void recordDiagnostic('restore', 'picker_opened')
      try {
        const restoreSelection = await chooseBackupForRestore()
        if (!restoreSelection) {
          void recordDiagnostic('restore', 'picker_cancelled')
          return
        }
        void recordDiagnostic('restore', 'selection_verified')
        const opened = modal.open({ kind: 'restore' })
        if (opened) {
          state.patch({ restoreSelection, restoreConfirmed: false, restoreSecret: '' })
        } else {
          void recordDiagnostic('restore', 'modal_refused')
          feedback.setErrorMessage('Close the open dialog first, then try restoring again.')
        }
      } catch (error) {
        void recordDiagnostic('restore', 'failed')
        feedback.setError(error)
      }
    },
    closeRestore() {
      if (state.value().restoringBackup) return
      modal.close('restore')
      state.patch({ restoreSelection: null, restoreConfirmed: false, restoreSecret: '', restorePresenceRequired: false, restorePresencePassword: '' })
    },
    async confirmRestore() {
      if (state.value().restorePresenceRequired) return
      await runRestore()
    },
    async confirmRestorePresence() {
      const current = state.value()
      const secret = current.restorePresencePassword
      if (!secret || current.restoringBackup) return
      feedback.clearError()
      try {
        await grantPresence(secret)
        state.patch({ restorePresencePassword: '', restorePresenceRequired: false })
        await runRestore()
      } catch (error) {
        feedback.setError(error)
      }
    },
    openDrill() {
      clearDrill()
      modal.open({ kind: 'backup-drill' })
      feedback.clearError()
    },
    closeDrill() {
      const current = state.value()
      if (current.drillWorking || current.drillRestoring) return
      modal.close('backup-drill')
      clearDrill()
    },
    async chooseDrillBackup() {
      if (state.value().drillWorking || state.value().drillRestoring) return
      state.patch({ drillError: '' })
      try {
        const drillSelection = await chooseBackupForRestore()
        if (drillSelection) {
          // A different file invalidates the prior proof and its credential.
          state.patch({ drillSelection, drillSecret: '', drillVerification: null, drillError: '' })        }
      } catch (error) {
        state.patch({ drillError: error instanceof Error ? error.message : 'Sesame could not open that backup.' })
      }
    },
    async verifyDrillBackup() {
      const current = state.value()
      if (!current.drillSelection || !current.drillSecret.trim() || current.drillWorking) return
      state.patch({ drillWorking: true, drillError: '' })
      try {
        state.patch({ drillVerification: await verifyBackup(current.drillSelection.token, current.drillSecret) })
        await refreshHealth()
      } catch (error) {
        state.patch({ drillVerification: null, drillError: error instanceof Error ? error.message : 'That backup could not be verified.' })
      } finally {
        state.patch({ drillWorking: false })
      }
    },
    async restoreVerifiedBackup() {
      await runDrillRestore()
    },
    async confirmDrillPresence() {
      const current = state.value()
      const secret = current.drillPresencePassword
      if (!secret || current.drillRestoring) return
      state.patch({ drillRestoring: true, drillError: '' })
      try {
        await grantPresence(secret)
        state.patch({ drillPresencePassword: '', drillPresenceRequired: false, drillRestoring: false })
        await runDrillRestore()
      } catch (error) {
        state.patch({ drillRestoring: false, drillError: error instanceof Error ? error.message : 'That master password did not match.' })
      }
    },
    clearSecrets() {
      modal.closeAll()
      state.set({
        restoreSelection: null,
        restoreConfirmed: false,
        restoreSecret: '',
        restoringBackup: false,
        restorePresenceRequired: false,
        restorePresencePassword: '',
        drillSelection: null,
        drillSecret: '',
        drillVerification: null,
        drillWorking: false,
        drillRestoring: false,
        drillPresenceRequired: false,
        drillPresencePassword: '',
        drillError: '',
        health: null,
        healthLoading: false,
        exportPresenceRequired: false,
        exportPresencePassword: '',
      })
    },
  }
}

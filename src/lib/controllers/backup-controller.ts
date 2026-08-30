import type { AppStores } from '../stores/app-stores'
import type { BackupSelection, BackupVerification, RecoveryHealth } from '../types'
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
    drillSelection: null as BackupSelection | null,
    drillSecret: '',
    drillVerification: null as BackupVerification | null,
    drillWorking: false,
    drillRestoring: false,
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
      drillError: '',
    })
  }

  async function applyRestoredVault(message: string) {
    vault.patch({ snapshot: null, loginCard: null, status: { ...(await getVaultStatus()), unlocked: false } })
    selection.patch({ activeItemId: null, activeItemKind: null, activeView: 'vault' })
    state.patch({ exportPresenceRequired: false, exportPresencePassword: '' })
    onRestored(message)
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
      state.patch({ restoreSelection: null, restoreConfirmed: false, restoreSecret: '' })
    },
    async confirmRestore() {
      const current = state.value()
      if (!current.restoreSelection || !current.restoreSecret) return
      if (vault.value().status.exists && !current.restoreConfirmed) return
      state.patch({ restoringBackup: true })
      feedback.clearError()
      try {
        const hadVault = vault.value().status.exists
        const restored = await restoreBackup(current.restoreSelection.source, current.restoreSecret)
        const message = restored.safetyBackupName
          ? `Backup restored. Sesame kept the previous vault as ${restored.safetyBackupName}.`
          : hadVault
            ? 'Backup restored.'
            : 'Backup restored. Unlock with the master password or recovery kit from that backup.'
        modal.close('restore')
        state.patch({ restoreSelection: null, restoreConfirmed: false, restoreSecret: '' })
        await applyRestoredVault(message)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ restoringBackup: false })
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
        state.patch({ drillVerification: await verifyBackup(current.drillSelection.source, current.drillSecret) })
        await refreshHealth()
      } catch (error) {
        state.patch({ drillVerification: null, drillError: error instanceof Error ? error.message : 'That backup could not be verified.' })
      } finally {
        state.patch({ drillWorking: false })
      }
    },
    async restoreVerifiedBackup() {
      const current = state.value()
      if (!current.drillSelection || !current.drillVerification || !current.drillSecret || current.drillRestoring) return
      state.patch({ drillRestoring: true, drillError: '' })
      try {
        const restored = await restoreBackup(current.drillSelection.source, current.drillSecret)
        const message = restored.safetyBackupName
          ? `Recovery drill complete. Sesame kept the previous vault as ${restored.safetyBackupName}.`
          : 'Recovery drill complete. The verified backup was restored.'
        modal.close('backup-drill')
        clearDrill()
        await applyRestoredVault(message)
      } catch (error) {
        state.patch({ drillError: error instanceof Error ? error.message : 'The verified backup could not be restored.' })
      } finally {
        state.patch({ drillRestoring: false })
      }
    },
    clearSecrets() {
      modal.closeAll()
      state.set({
        restoreSelection: null,
        restoreConfirmed: false,
        restoreSecret: '',
        restoringBackup: false,
        drillSelection: null,
        drillSecret: '',
        drillVerification: null,
        drillWorking: false,
        drillRestoring: false,
        drillError: '',
        health: null,
        healthLoading: false,
        exportPresenceRequired: false,
        exportPresencePassword: '',
      })
    },
  }
}

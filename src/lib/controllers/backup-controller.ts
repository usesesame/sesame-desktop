import type { AppStores } from '../stores/app-stores'
import type { BackupSelection, BackupVerification, RecoveryHealth } from '../types'
import {
  chooseBackupForRestore,
  createBackup,
  exportBackup,
  getRecoveryHealth,
  getVaultStatus,
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
      try {
        const name = await exportBackup()
        if (name) feedback.showNotice('Backup exported', `${name} is still encrypted.`)
        await refreshHealth()
      } catch (error) {
        feedback.setError(error)
      }
    },
    async beginRestore() {
      feedback.clearError()
      try {
        const restoreSelection = await chooseBackupForRestore()
        if (restoreSelection) {
          const opened = modal.open({ kind: 'restore' })
          if (opened) state.patch({ restoreSelection, restoreConfirmed: false, restoreSecret: '' })
        }
      } catch (error) {
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
      if (!current.restoreSelection || !current.restoreConfirmed || !current.restoreSecret) return
      state.patch({ restoringBackup: true })
      feedback.clearError()
      try {
        const restored = await restoreBackup(current.restoreSelection.source, current.restoreSecret)
        const message = restored.safetyBackupName
          ? `Backup restored. Sesame kept the previous vault as ${restored.safetyBackupName}.`
          : 'Backup restored.'
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
      })
    },
  }
}

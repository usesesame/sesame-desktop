import type { AppStores } from '../stores/app-stores'
import type { ItemKind, VaultSnapshot } from '../types'
import {
  completeRecoverySetup,
  createVault,
  getVaultStatus,
  lockVault,
  resumeRecoverySetup,
  unlockVault,
  unlockWithPin,
  unlockWithRecovery,
  unlockWithWindowsHello,
} from '../vault'
import { vaultItems } from '../vault-items'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'
import type { OnboardingController } from './onboarding-controller'

interface UnlockControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  selectItem: (id: string, kind: ItemKind) => Promise<void>
  clearSelection: () => void
  clearSessionState: () => void
  rejectBrowserFill: () => Promise<void>
  refreshActiveView: () => Promise<void>
  openPinSetup: () => void
  onboarding: OnboardingController
  modal: ModalController
}

export function createUnlockController(options: UnlockControllerOptions) {
  const { stores, feedback, onboarding, modal } = options
  const { selection, vault } = stores
  const state = controllerStore({
    masterPassword: '',
    confirmPassword: '',
    unlockPin: '',
    isWorking: true,
    recoveryKit: '',
    recoveryConfirmed: false,
    recoveryUnlockOpen: false,
    restoreMessage: '',
    refreshingVault: false,
    // Set only from the Rust guard's event, never counted down here.
    idleWarningSeconds: null as number | null,
  })

  async function openFirst(snapshot: VaultSnapshot) {
    const first = vaultItems(snapshot)[0]
    if (first) await options.selectItem(first.id, first.kind)
    else options.clearSelection()
  }

  async function installExistingUnlock(snapshot: VaultSnapshot): Promise<boolean> {
    let status = await getVaultStatus()
    if (status.onboardingRequired) {
      let recoveryKit: string
      try {
        recoveryKit = await resumeRecoverySetup()
        status = await getVaultStatus()
      } catch (error) {
        await lockVault().catch(() => undefined)
        throw error
      }
      vault.patch({ snapshot, status })
      state.patch({ recoveryKit, recoveryConfirmed: false, masterPassword: '', confirmPassword: '' })
      onboarding.startAfterVaultCreation()
      return false
    }
    vault.patch({ snapshot, status })
    await openFirst(snapshot)
    return true
  }

  async function loadVault() {
    const snapshot = await unlockVault({ masterPassword: '' }, true)
    await installExistingUnlock(snapshot)
  }

  function clearUnlockSecrets() {
    state.patch({ masterPassword: '', confirmPassword: '', unlockPin: '', recoveryUnlockOpen: false })
  }

  function applyLockedUi(message: string) {
    options.clearSessionState()
    clearUnlockSecrets()
    state.patch({ idleWarningSeconds: null })
    modal.lockCleared()
    onboarding.lockCleared()
    vault.patch({ snapshot: null, loginCard: null, status: { ...vault.value().status, unlocked: false } })
    selection.patch({ activeItemId: null, activeItemKind: null, activeView: 'vault', collectionFilter: null, categoryFilter: null })
    feedback.showNotice('Vault locked', message)
  }

  return {
    state,
    loadVault,
    clearUnlockSecrets,
    /// Ignored while locked: a late warning must not paint a countdown over the unlock screen.
    showIdleWarning(secondsLeft: number) {
      if (!vault.value().status.unlocked) return
      state.patch({ idleWarningSeconds: Math.max(1, Math.round(secondsLeft)) })
    },
    clearIdleWarning() {
      state.patch({ idleWarningSeconds: null })
    },
    async loadStatus() {
      state.patch({ isWorking: true })
      feedback.clearError()
      try {
        const status = await getVaultStatus()
        vault.patch({ status })
        if (status.unlocked) await loadVault()
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ isWorking: false })
      }
    },
    async refreshCurrentView() {
      if (state.value().refreshingVault || !vault.value().status.unlocked) return
      state.patch({ refreshingVault: true })
      feedback.clearError()
      const selectedId = selection.value().activeItemId
      try {
        const snapshot = await unlockVault({ masterPassword: '' }, true)
        vault.patch({ snapshot })
        const selected = selectedId ? vaultItems(snapshot).find((item) => item.id === selectedId) : undefined
        if (selected) await options.selectItem(selected.id, selected.kind)
        else await openFirst(snapshot)
        await options.refreshActiveView()
        feedback.showNotice('Vault view refreshed', 'The current view is up to date.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ refreshingVault: false })
      }
    },
    async submitMasterPassword() {
      const current = state.value()
      const status = vault.value().status
      feedback.clearError()
      if (!status.exists && current.masterPassword.length < 12) return feedback.setErrorMessage('Use at least 12 characters. A memorable passphrase is usually best.')
      if (!status.exists && current.masterPassword !== current.confirmPassword) return feedback.setErrorMessage('Those master passwords do not match.')

      state.patch({ isWorking: true })
      try {
        if (!status.exists) {
          const setup = await createVault({ masterPassword: current.masterPassword })
          vault.patch({ snapshot: setup.snapshot, status: { ...status, exists: true, unlocked: true, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: true, vaultId: setup.snapshot.vaultId, revision: setup.snapshot.revision } })
          state.patch({ recoveryKit: setup.recoveryKit, recoveryConfirmed: false, masterPassword: '', confirmPassword: '' })
          onboarding.startAfterVaultCreation()
          return
        }
        let snapshot: VaultSnapshot
        if (current.recoveryUnlockOpen) {
          try {
            snapshot = await unlockVault({ masterPassword: current.masterPassword })
          } catch {
            try {
              snapshot = await unlockWithRecovery(current.masterPassword.trim().toUpperCase())
            } catch {
              feedback.setErrorMessage('That master password or recovery kit is not correct.')
              return
            }
          }
        } else {
          snapshot = await unlockVault({ masterPassword: current.masterPassword })
        }
        state.patch({ masterPassword: '', confirmPassword: '', recoveryUnlockOpen: false, restoreMessage: '' })
        const ready = await installExistingUnlock(snapshot)
        if (ready) feedback.showNotice('Vault unlocked', status.preview ? 'Preview mode does not create a vault file.' : 'Your logins are ready.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ isWorking: false })
      }
    },
    async unlockUsingPin() {
      const current = state.value()
      if (current.unlockPin.length !== 6 || current.isWorking) return
      state.patch({ isWorking: true })
      feedback.clearError()
      try {
        const snapshot = await unlockWithPin(current.unlockPin)
        state.patch({ unlockPin: '', restoreMessage: '' })
        await installExistingUnlock(snapshot)
      } catch (error) {
        state.patch({ unlockPin: '' })
        feedback.setError(error)
      } finally {
        state.patch({ isWorking: false })
      }
    },
    async unlockUsingHello() {
      const current = state.value()
      if (current.isWorking) return
      state.patch({ isWorking: true })
      feedback.clearError()
      try {
        const snapshot = await unlockWithWindowsHello()
        state.patch({ restoreMessage: '' })
        await installExistingUnlock(snapshot)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ isWorking: false })
      }
    },
    continueRecoveryKitSetup() {
      onboarding.advance()
    },
    async finishRecoveryKit() {
      const recoveryKit = state.value().recoveryKit
      if (!recoveryKit || state.value().isWorking) return
      state.patch({ isWorking: true })
      feedback.clearError()
      try {
        await completeRecoverySetup(recoveryKit)
        const status = await getVaultStatus()
        vault.patch({ status })
        state.patch({ recoveryKit: '', recoveryConfirmed: false })
        feedback.showNotice('Vault set up', 'Create a backup before importing anything important.')
        const first = vaultItems(vault.value().snapshot)[0]
        if (first) await options.selectItem(first.id, first.kind)
        onboarding.advance()
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ isWorking: false })
      }
    },
    applyLockedUi,
    async lock(message = 'Vault locked.') {
      await options.rejectBrowserFill()
      await lockVault()
      applyLockedUi(message)
    },
    markVaultDeleted(message: string) {
      options.clearSessionState()
      clearUnlockSecrets()
      onboarding.resetAfterVaultDeletion()
      vault.patch({ snapshot: null, loginCard: null, status: { exists: false, unlocked: false, preview: vault.value().status.preview, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 0 } })
      selection.patch({ activeItemId: null, activeItemKind: null, activeView: 'vault' })
      state.patch({ restoreMessage: message })
    },
    markRestored(message: string) {
      options.clearSessionState()
      clearUnlockSecrets()
      state.patch({ restoreMessage: message })
    },
    clearSecrets() {
      state.patch({ masterPassword: '', confirmPassword: '', unlockPin: '', recoveryKit: '', recoveryConfirmed: false, recoveryUnlockOpen: false })
    },
  }
}

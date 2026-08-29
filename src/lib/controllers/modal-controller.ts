import type { AppStores } from '../stores/app-stores'
import type { FeedbackController } from './feedback-controller'
import { controllerStore } from './controller-store'

export type ActiveModal =
  | { kind: 'pin-setup' }
  | { kind: 'change-master-password' }
  | { kind: 'import' }
  | { kind: 'restore' }
  | { kind: 'backup-drill' }
  | { kind: 'login-editor' }
  | { kind: 'delete-login'; entryId: string }
  | { kind: 'identity-editor' }
  | { kind: 'delete-identity'; identityId: string }
  | { kind: 'secure-note-editor' }
  | { kind: 'delete-secure-note'; noteId: string }
  | { kind: 'card-editor' }
  | { kind: 'delete-card'; cardId: string }
  | { kind: 'wifi-network-editor' }
  | { kind: 'delete-wifi-network'; networkId: string }
  | { kind: 'ssh-key-editor' }
  | { kind: 'delete-ssh-key'; keyId: string }
  | { kind: 'software-license-editor' }
  | { kind: 'delete-software-license'; licenseId: string }
  | { kind: 'document-editor' }
  | { kind: 'delete-document'; documentId: string }
  | { kind: 'custom-record-editor' }
  | { kind: 'delete-custom-record'; recordId: string }
  | { kind: 'data-controls' }
  | { kind: 'delete-vault' }
  | { kind: 'merge' }
  | { kind: 'folder-manager' }
  | { kind: 'folder-name' }
  | null

export type ModalKind = NonNullable<ActiveModal>['kind']

export interface ModalState {
  active: ActiveModal
}

export interface ModalControllerOptions {
  stores: AppStores
  feedback: FeedbackController
}

export interface ModalController {
  state: ReturnType<typeof controllerStore<ModalState>>
  open(modal: ActiveModal): boolean
  close(kind?: ModalKind): void
  closeAll(): void
  lockCleared(): void
  browserFillMayShow(): boolean
  identityFillMayShow(): boolean
  cardFillMayShow(): boolean
  browserSaveMayShow(): boolean
}

export function createModalController({ stores, feedback }: ModalControllerOptions): ModalController {
  const state = controllerStore<ModalState>({ active: null })

  function open(modal: ActiveModal): boolean {
    if (modal === null) return true
    if (stores.browserFill.value().request || stores.browserIdentityFill.value().request || stores.browserCardFill.value().request || stores.browserSave.value().request) return false
    const current = state.value().active
    if (current !== null && modalKindsConflict(current.kind, modal.kind)) {
      return false
    }
    clearSecretBearingModal(current)
    state.patch({ active: modal })
    feedback.clearError()
    return true
  }

  function close(kind?: ModalKind) {
    const current = state.value().active
    if (current === null) return
    if (kind && current.kind !== kind) return
    clearSecretBearingModal(current)
    state.patch({ active: null })
  }

  function closeAll() {
    const current = state.value().active
    if (current) clearSecretBearingModal(current)
    state.patch({ active: null })
  }

  function lockCleared() {
    closeAll()
  }

  function browserFillMayShow(): boolean {
    const current = state.value().active
    if (current === null && !stores.browserIdentityFill.value().request && !stores.browserCardFill.value().request && !stores.browserSave.value().request) return true
    // Only one browser-originated prompt at a time, matching Rust.
    return false
  }

  function identityFillMayShow(): boolean {
    const current = state.value().active
    if (current === null && !stores.browserFill.value().request && !stores.browserCardFill.value().request && !stores.browserSave.value().request) return true
    return false
  }

  function cardFillMayShow(): boolean {
    const current = state.value().active
    return current === null && !stores.browserFill.value().request && !stores.browserIdentityFill.value().request && !stores.browserSave.value().request
  }

  function browserSaveMayShow(): boolean {
    const current = state.value().active
    if (current === null && !stores.browserFill.value().request && !stores.browserIdentityFill.value().request && !stores.browserCardFill.value().request) return true
    return false
  }

  return {
    state,
    open,
    close,
    closeAll,
    lockCleared,
    browserFillMayShow,
    identityFillMayShow,
    cardFillMayShow,
    browserSaveMayShow,
  }
}

function modalKindsConflict(a: NonNullable<ActiveModal>['kind'], b: NonNullable<ActiveModal>['kind']): boolean {
  if (a === 'restore' || b === 'restore') return true
  if (a === 'delete-login' || b === 'delete-login') return true
  return true
}

function clearSecretBearingModal(modal: ActiveModal) {
  void modal
}

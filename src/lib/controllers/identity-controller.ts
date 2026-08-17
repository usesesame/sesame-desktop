import type { AppStores } from '../stores/app-stores'
import type { Identity, IdentityInput, LegacyField } from '../types'
import { deleteIdentity, getIdentity, recordDiagnostic, saveIdentity } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyIdentityDraft(): IdentityInput {
  return {
    label: '', fullName: '', email: '', phone: '',
    addressLine1: '', addressLine2: '', city: '', region: '', postalCode: '', country: '',
  }
}

function draftFrom(identity: Identity): IdentityInput {
  const { id, label, fullName, email, phone, addressLine1, addressLine2, city, region, postalCode, country } = identity
  return { id, label, fullName, email, phone, addressLine1, addressLine2, city, region, postalCode, country }
}

interface IdentityControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createIdentityController({ stores, feedback, modal }: IdentityControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    identityDraft: emptyIdentityDraft(),
    editorTitle: 'Add an identity',
    savingIdentity: false,
    loadingIdentity: false,
    legacyFields: [] as LegacyField[],
    deleteCandidate: null as { id: string; label: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('identity-editor')
    state.patch({ identityDraft: emptyIdentityDraft(), legacyFields: [] })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'identity-editor' })
      if (!opened) return
      state.patch({ identityDraft: emptyIdentityDraft(), editorTitle: 'Add an identity', legacyFields: [] })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'identity-editor' })
      if (!opened) return
      state.patch({ loadingIdentity: true })
      feedback.clearError()
      try {
        const identity = await getIdentity(id)
        state.patch({ identityDraft: draftFrom(identity), editorTitle: 'Edit identity', legacyFields: identity.legacyFields ?? [] })
      } catch (error) {
        modal.close('identity-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingIdentity: false })
      }
    },
    closeEditor,
    setDraft(identityDraft: IdentityInput) {
      state.patch({ identityDraft })
    },
    async save() {
      const draft = state.value().identityDraft
      state.patch({ savingIdentity: true })
      feedback.clearError()
      try {
        const result = await saveIdentity(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Identity updated' : 'Identity saved', `${draft.label.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingIdentity: false })
      }
    },
    requestDelete(id: string, label: string) {
      const opened = modal.open({ kind: 'delete-identity', identityId: id })
      if (opened) state.patch({ deleteCandidate: { id, label } })
    },
    cancelDelete() {
      modal.close('delete-identity')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteIdentity(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-identity')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Identity deleted', `${candidate.label} was removed from your vault.`)
      } catch (error) {
        void recordDiagnostic('vault_save', 'failed')
        feedback.setError(error)
      } finally {
        state.patch({ deleteWorking: false })
      }
    },
    clearSecrets() {
      modal.closeAll()
      state.set({
        identityDraft: emptyIdentityDraft(),
        editorTitle: 'Add an identity',
        savingIdentity: false,
        loadingIdentity: false,
        legacyFields: [],
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type IdentityController = ReturnType<typeof createIdentityController>

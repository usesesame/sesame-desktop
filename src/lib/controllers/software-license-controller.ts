import type { AppStores } from '../stores/app-stores'
import type { SoftwareLicense, SoftwareLicenseInput } from '../types'
import { deleteSoftwareLicense, getSoftwareLicense, recordDiagnostic, saveSoftwareLicense } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyLicenseDraft(): SoftwareLicenseInput {
  return { title: '', licenseKey: '', productName: '', purchasedFrom: '', purchaseDate: '', notes: '', tags: [] }
}

function draftFrom(license: SoftwareLicense): SoftwareLicenseInput {
  const { id, title, licenseKey, productName, purchasedFrom, purchaseDate, notes, tags } = license
  return { id, title, licenseKey, productName, purchasedFrom, purchaseDate, notes, tags }
}

interface SoftwareLicenseControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createSoftwareLicenseController({ stores, feedback, modal }: SoftwareLicenseControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    licenseDraft: emptyLicenseDraft(),
    editorTitle: 'Add a licence',
    savingLicense: false,
    loadingLicense: false,
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('software-license-editor')
    state.patch({ licenseDraft: emptyLicenseDraft() })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'software-license-editor' })
      if (!opened) return
      state.patch({ licenseDraft: emptyLicenseDraft(), editorTitle: 'Add a licence' })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'software-license-editor' })
      if (!opened) return
      state.patch({ loadingLicense: true })
      feedback.clearError()
      try {
        const license = await getSoftwareLicense(id)
        state.patch({ licenseDraft: draftFrom(license), editorTitle: 'Edit licence' })
      } catch (error) {
        modal.close('software-license-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingLicense: false })
      }
    },
    closeEditor,
    setDraft(licenseDraft: SoftwareLicenseInput) {
      state.patch({ licenseDraft })
    },
    async save() {
      const draft = state.value().licenseDraft
      state.patch({ savingLicense: true })
      feedback.clearError()
      try {
        const result = await saveSoftwareLicense(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Licence updated' : 'Licence saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingLicense: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-software-license', licenseId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-software-license')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteSoftwareLicense(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-software-license')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Licence deleted', `${candidate.title} was removed from your vault.`)
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
        licenseDraft: emptyLicenseDraft(),
        editorTitle: 'Add a licence',
        savingLicense: false,
        loadingLicense: false,
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type SoftwareLicenseController = ReturnType<typeof createSoftwareLicenseController>

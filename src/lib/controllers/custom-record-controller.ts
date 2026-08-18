import type { AppStores } from '../stores/app-stores'
import type { CustomRecord, CustomRecordInput } from '../types'
import { deleteCustomRecord, getCustomRecord, recordDiagnostic, saveCustomRecord } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyRecordDraft(): CustomRecordInput {
  return { title: '', fields: [], notes: '', tags: [] }
}

function draftFrom(record: CustomRecord): CustomRecordInput {
  const { id, title, fields, notes, tags } = record
  return { id, title, fields, notes, tags: tags ?? [] }
}

interface CustomRecordControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createCustomRecordController({ stores, feedback, modal }: CustomRecordControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    recordDraft: emptyRecordDraft(),
    editorTitle: 'Add a record',
    savingRecord: false,
    loadingRecord: false,
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('custom-record-editor')
    state.patch({ recordDraft: emptyRecordDraft() })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'custom-record-editor' })
      if (!opened) return
      state.patch({ recordDraft: emptyRecordDraft(), editorTitle: 'Add a record' })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'custom-record-editor' })
      if (!opened) return
      state.patch({ loadingRecord: true })
      feedback.clearError()
      try {
        const record = await getCustomRecord(id)
        state.patch({ recordDraft: draftFrom(record), editorTitle: 'Edit record' })
      } catch (error) {
        modal.close('custom-record-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingRecord: false })
      }
    },
    closeEditor,
    setDraft(recordDraft: CustomRecordInput) {
      state.patch({ recordDraft })
    },
    async save() {
      const draft = state.value().recordDraft
      state.patch({ savingRecord: true })
      feedback.clearError()
      try {
        const result = await saveCustomRecord(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Record updated' : 'Record saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingRecord: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-custom-record', recordId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-custom-record')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteCustomRecord(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-custom-record')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Record deleted', `${candidate.title} was removed from your vault.`)
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
        recordDraft: emptyRecordDraft(),
        editorTitle: 'Add a record',
        savingRecord: false,
        loadingRecord: false,
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type CustomRecordController = ReturnType<typeof createCustomRecordController>

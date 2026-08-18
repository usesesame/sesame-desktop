import type { AppStores } from '../stores/app-stores'
import type { LegacyField, SecureNote, SecureNoteInput } from '../types'
import { deleteSecureNote, getSecureNote, recordDiagnostic, saveSecureNote } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyNoteDraft(): SecureNoteInput {
  return { title: '', content: '', tags: [] }
}

function draftFrom(note: SecureNote): SecureNoteInput {
  const { id, title, content, tags } = note
  return { id, title, content, tags: tags ?? [] }
}

interface SecureNoteControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createSecureNoteController({ stores, feedback, modal }: SecureNoteControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    noteDraft: emptyNoteDraft(),
    editorTitle: 'Add a note',
    savingNote: false,
    loadingNote: false,
    legacyFields: [] as LegacyField[],
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('secure-note-editor')
    state.patch({ noteDraft: emptyNoteDraft(), legacyFields: [] })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'secure-note-editor' })
      if (!opened) return
      state.patch({ noteDraft: emptyNoteDraft(), editorTitle: 'Add a note', legacyFields: [] })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'secure-note-editor' })
      if (!opened) return
      state.patch({ loadingNote: true })
      feedback.clearError()
      try {
        const note = await getSecureNote(id)
        state.patch({ noteDraft: draftFrom(note), editorTitle: 'Edit note', legacyFields: note.legacyFields ?? [] })
      } catch (error) {
        modal.close('secure-note-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingNote: false })
      }
    },
    closeEditor,
    setDraft(noteDraft: SecureNoteInput) {
      state.patch({ noteDraft })
    },
    async save() {
      const draft = state.value().noteDraft
      state.patch({ savingNote: true })
      feedback.clearError()
      try {
        const result = await saveSecureNote(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Note updated' : 'Note saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingNote: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-secure-note', noteId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-secure-note')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteSecureNote(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-secure-note')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Note deleted', `${candidate.title} was removed from your vault.`)
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
        noteDraft: emptyNoteDraft(),
        editorTitle: 'Add a note',
        savingNote: false,
        loadingNote: false,
        legacyFields: [],
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type SecureNoteController = ReturnType<typeof createSecureNoteController>

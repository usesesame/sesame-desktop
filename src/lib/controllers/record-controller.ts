import type { AppStores } from '../stores/app-stores'
import type { LegacyField, VaultSnapshot } from '../types'
import { recordDiagnostic } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ActiveModal, ModalController, ModalKind } from './modal-controller'

export interface RecordControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

interface RecordLike {
  id: string
  legacyFields?: LegacyField[]
}

export interface RecordConfig<TItem extends RecordLike, TInput extends { id?: string }> {
  editorModal: NonNullable<ActiveModal>
  deleteModalKind: ModalKind
  deleteModal(id: string): NonNullable<ActiveModal>
  emptyDraft(): TInput
  draftFrom(item: TItem): TInput
  draftTitle(draft: TInput): string
  api: {
    get(id: string): Promise<TItem>
    save(input: TInput): Promise<{ id: string; snapshot: VaultSnapshot }>
    delete(id: string): Promise<{ deletedId: string; snapshot: VaultSnapshot }>
  }
  copy: {
    addTitle: string
    editTitle: string
    savedNotice(isNew: boolean, title: string): { title: string; body: string }
    deletedNotice(title: string): { title: string; body: string }
  }
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createRecordController<TItem extends RecordLike, TInput extends { id?: string }>(
  { stores, feedback, modal }: RecordControllerOptions,
  config: RecordConfig<TItem, TInput>,
) {
  const { vault } = stores
  const editorModalKind = config.editorModal.kind
  const state = controllerStore({
    draft: config.emptyDraft(),
    editorTitle: config.copy.addTitle,
    saving: false,
    loading: false,
    legacyFields: [] as LegacyField[],
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close(editorModalKind)
    state.patch({ draft: config.emptyDraft(), legacyFields: [] })
  }

  return {
    state,
    openNew() {
      const opened = modal.open(config.editorModal)
      if (!opened) return
      state.patch({ draft: config.emptyDraft(), editorTitle: config.copy.addTitle, legacyFields: [] })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open(config.editorModal)
      if (!opened) return
      state.patch({ loading: true })
      feedback.clearError()
      try {
        const item = await config.api.get(id)
        state.patch({ draft: config.draftFrom(item), editorTitle: config.copy.editTitle, legacyFields: item.legacyFields ?? [] })
      } catch (error) {
        modal.close(editorModalKind)
        feedback.setError(error)
      } finally {
        state.patch({ loading: false })
      }
    },
    closeEditor,
    setDraft(draft: TInput) {
      state.patch({ draft })
    },
    async save() {
      const draft = state.value().draft
      state.patch({ saving: true })
      feedback.clearError()
      try {
        const result = await config.api.save(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        const notice = config.copy.savedNotice(!draft.id, config.draftTitle(draft))
        feedback.showNotice(notice.title, notice.body)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ saving: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open(config.deleteModal(id))
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close(config.deleteModalKind)
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await config.api.delete(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close(config.deleteModalKind)
        state.patch({ deleteCandidate: null })
        const notice = config.copy.deletedNotice(candidate.title)
        feedback.showNotice(notice.title, notice.body)
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
        draft: config.emptyDraft(),
        editorTitle: config.copy.addTitle,
        saving: false,
        loading: false,
        legacyFields: [],
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type RecordController<TItem extends RecordLike, TInput extends { id?: string }> = ReturnType<
  typeof createRecordController<TItem, TInput>
>

import type { AppStores } from '../stores/app-stores'
import type { ItemPreview } from '../types'
import { previewTrashedItem, recordDiagnostic, restoreTrashedItem } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'

interface TrashControllerOptions {
  stores: AppStores
  feedback: FeedbackController
}

/// Restore is never blind: a non-secret preview for that one id comes first.
export function createTrashController({ stores, feedback }: TrashControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    restoringId: null as string | null,
    previewingId: null as string | null,
    previewId: null as string | null,
    preview: null as ItemPreview | null,
  })

  return {
    state,
    async preview(id: string) {
      state.patch({ previewingId: id })
      feedback.clearError()
      try {
        const preview = await previewTrashedItem(id)
        state.patch({ previewId: id, preview })
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ previewingId: null })
      }
    },
    cancelPreview() {
      state.patch({ previewId: null, preview: null })
    },
    async restore(id: string) {
      state.patch({ restoringId: id })
      feedback.clearError()
      try {
        const result = await restoreTrashedItem(id)
        vault.patch({ snapshot: result.snapshot })
        state.patch({ previewId: null, preview: null })
        feedback.showNotice('Item restored', 'The deleted item is back in your vault.')
      } catch (error) {
        void recordDiagnostic('vault_save', 'failed')
        feedback.setError(error)
      } finally {
        state.patch({ restoringId: null })
      }
    },
    clearSecrets() {
      state.set({ restoringId: null, previewingId: null, previewId: null, preview: null })
    },
  }
}

export type TrashController = ReturnType<typeof createTrashController>

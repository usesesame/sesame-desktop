import type { AppStores } from '../stores/app-stores'
import type { ItemPreview } from '../types'
import { previewHistoryVersion, recordDiagnostic, restoreHistoryVersion } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'

interface HistoryControllerOptions {
  stores: AppStores
  feedback: FeedbackController
}

/// Restore is never blind: a non-secret preview for that one version comes first.
export function createHistoryController({ stores, feedback }: HistoryControllerOptions) {
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
        const preview = await previewHistoryVersion(id)
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
        const result = await restoreHistoryVersion(id)
        vault.patch({ snapshot: result.snapshot })
        state.patch({ previewId: null, preview: null })
        feedback.showNotice('Version restored', 'The item was reverted to this version.')
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

export type HistoryController = ReturnType<typeof createHistoryController>

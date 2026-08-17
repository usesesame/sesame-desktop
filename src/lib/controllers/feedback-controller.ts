import { controllerStore } from './controller-store'

export interface AppNotice {
  title: string
  message: string
}

export function messageFor(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Your vault has not been changed.'
}

export function createFeedbackController() {
  const state = controllerStore<{ errorMessage: string; notice: AppNotice | null }>({
    errorMessage: '',
    notice: null,
  })
  let noticeTimer: ReturnType<typeof window.setTimeout> | undefined

  function clearNoticeTimer() {
    if (noticeTimer) window.clearTimeout(noticeTimer)
    noticeTimer = undefined
  }

  return {
    state,
    clearError() {
      state.patch({ errorMessage: '' })
    },
    setError(error: unknown) {
      state.patch({ errorMessage: messageFor(error) })
    },
    setErrorMessage(errorMessage: string) {
      state.patch({ errorMessage })
    },
    showNotice(title: string, message: string) {
      clearNoticeTimer()
      state.patch({ notice: { title, message } })
      noticeTimer = window.setTimeout(() => state.patch({ notice: null }), 4_800)
    },
    dismissNotice() {
      clearNoticeTimer()
      state.patch({ notice: null })
    },
    destroy() {
      clearNoticeTimer()
      state.set({ errorMessage: '', notice: null })
    },
  }
}

export type FeedbackController = ReturnType<typeof createFeedbackController>

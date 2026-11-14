import { controllerStore } from './controller-store'

export interface NoticeAction {
  label: string
  run: () => void
}

export interface AppNotice {
  title: string
  message: string
  action?: NoticeAction
}

const NOTICE_MS = 4_800
const NOTICE_WITH_ACTION_MS = 9_000
const NOTICE_MIN_READ_MS = 1_000

export function messageFor(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Your vault has not been changed.'
}

export function createFeedbackController() {
  const state = controllerStore<{ errorMessage: string; notice: AppNotice | null }>({
    errorMessage: '',
    notice: null,
  })
  let noticeTimer: ReturnType<typeof window.setTimeout> | undefined
  let noticeStartedAt = 0
  let noticeRemainingMs = NOTICE_MS
  let noticeHeld = false

  function clearNoticeTimer() {
    if (noticeTimer) window.clearTimeout(noticeTimer)
    noticeTimer = undefined
  }

  function startNoticeTimer(durationMs: number) {
    clearNoticeTimer()
    noticeStartedAt = Date.now()
    noticeRemainingMs = durationMs
    noticeTimer = window.setTimeout(() => state.patch({ notice: null }), durationMs)
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
    showNotice(title: string, message: string, action?: NoticeAction) {
      const duration = action ? NOTICE_WITH_ACTION_MS : NOTICE_MS
      state.patch({ notice: action ? { title, message, action } : { title, message } })
      if (noticeHeld) {
        clearNoticeTimer()
        noticeRemainingMs = duration
        return
      }
      startNoticeTimer(duration)
    },
    holdNotice() {
      noticeHeld = true
      if (!noticeTimer) return
      clearNoticeTimer()
      noticeRemainingMs = Math.max(NOTICE_MIN_READ_MS, noticeRemainingMs - (Date.now() - noticeStartedAt))
    },
    resumeNotice() {
      noticeHeld = false
      if (noticeTimer || !state.value().notice) return
      startNoticeTimer(noticeRemainingMs)
    },
    dismissNotice() {
      noticeHeld = false
      clearNoticeTimer()
      state.patch({ notice: null })
    },
    destroy() {
      noticeHeld = false
      clearNoticeTimer()
      state.set({ errorMessage: '', notice: null })
    },
  }
}

export type FeedbackController = ReturnType<typeof createFeedbackController>

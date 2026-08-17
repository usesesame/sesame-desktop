import type { AppStores } from '../stores/app-stores'
import type { BrowserSaveRequest } from '../types'
import {
  getPendingBrowserSave,
  onVaultLocked,
  previewMode,
  recordDiagnostic,
  resolveBrowserSave as resolveBrowserSaveRequest,
  subscribeBrowserSave,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface BrowserSaveControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createBrowserSaveController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: BrowserSaveControllerOptions) {
  const { browserSave, vault } = stores
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: BrowserSaveRequest) {
    if (!modal.browserSaveMayShow() || blockingOverlayActive()) {
      void resolveBrowserSaveRequest(request.approvalId, false)
      return
    }
    const current = browserSave.value().request
    if (current?.approvalId === request.approvalId) return
    if (current) void resolveBrowserSaveRequest(current.approvalId, false)
    browserSave.patch({
      request,
      selectedId: request.kind === 'update' && request.candidates.length === 1 ? request.candidates[0].id : '',
      working: false,
    })
  }

  async function syncPending() {
    if (previewMode || browserSave.value().syncWorking) return
    browserSave.patch({ syncWorking: true })
    try {
      const pending = await getPendingBrowserSave()
      const current = browserSave.value()
      browserSave.patch({ syncFailed: false })
      if (pending && current.request?.approvalId !== pending.approvalId) receive(pending)
      else if (!pending && current.request && !current.working) browserSave.patch({ request: null, selectedId: '' })
    } catch {
      if (!browserSave.value().syncFailed) {
        browserSave.patch({ syncFailed: true })
        void recordDiagnostic('browser_host', 'save_listener_failed')
      }
    } finally {
      browserSave.patch({ syncWorking: false })
    }
  }

  function scheduleSync() {
    if (disposed) return
    syncTimer = window.setTimeout(() => {
      void syncPending().finally(scheduleSync)
    }, browserSave.value().request ? 500 : 3_000)
  }

  // selectedId goes only when the user chose it; the command refuses rather than guesses.
  async function resolve(approved: boolean) {
    const current = browserSave.value()
    const request = current.request
    if (!request || current.working) return
    const selectedId = request.kind === 'update' ? current.selectedId || undefined : undefined
    browserSave.patch({ working: true })
    try {
      const result = await resolveBrowserSaveRequest(request.approvalId, approved, selectedId)
      if (approved && result) {
        vault.patch({ snapshot: result.snapshot })
        const label = request.title.trim() || request.hostname
        feedback.showNotice(
          request.kind === 'update' ? 'Login updated' : 'Login saved',
          request.kind === 'update'
            ? `The saved password for ${label} was updated.`
            : `${label} is stored in your vault.`
        )
      }
    } catch (error) {
      if (approved) feedback.setError(error)
    } finally {
      if (browserSave.value().request?.approvalId === request.approvalId) browserSave.patch({ request: null, selectedId: '' })
      browserSave.patch({ working: false })
    }
  }

  return {
    receive,
    syncPending,
    resolve,
    clearSecrets() {
      const pending = browserSave.value().request
      if (pending) void resolveBrowserSaveRequest(pending.approvalId, false)
      browserSave.patch({ request: null, selectedId: '', working: false, syncWorking: false })
    },
    start() {
      disposed = false
      if (previewMode) return () => {}
      void subscribeBrowserSave({
        request: (payload) => disposed ? void resolveBrowserSaveRequest(payload.approvalId, false) : receive(payload),
        cancelled: (payload) => {
          if (browserSave.value().request?.approvalId === payload.approvalId) browserSave.patch({ request: null, selectedId: '', working: false })
        },
      }).then((stop) => {
        if (disposed) stop()
        else stopSubscription = stop
      }).catch(() => void recordDiagnostic('browser_host', 'save_listener_failed'))
      void onVaultLocked(() => { if (!disposed) handleVaultLocked() }).then((stop) => {
        if (disposed) stop()
        else stopLockedListener = stop
      }).catch(() => void recordDiagnostic('renderer', 'vault_lock_listener_failed'))
      void syncPending()
      scheduleSync()
      return () => {
        disposed = true
        stopSubscription?.()
        stopLockedListener?.()
        stopSubscription = undefined
        stopLockedListener = undefined
        if (syncTimer) window.clearTimeout(syncTimer)
        syncTimer = undefined
        const pending = browserSave.value().request
        if (pending) void resolveBrowserSaveRequest(pending.approvalId, false)
      }
    },
  }
}

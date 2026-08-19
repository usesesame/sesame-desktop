import type { AppStores } from '../stores/app-stores'
import type { BrowserFillRequest } from '../types'
import {
  getPendingBrowserFill,
  onVaultLocked,
  previewMode,
  recordDiagnostic,
  resolveBrowserFill as resolveBrowserFillRequest,
  subscribeBrowserFill,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface BrowserFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createBrowserFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: BrowserFillControllerOptions) {
  const { browserFill } = stores
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: BrowserFillRequest) {
    if (!request.candidates.length) {
      void resolveBrowserFillRequest(request.approvalId, null)
      return
    }
    if (!modal.browserFillMayShow() || blockingOverlayActive()) {
      void resolveBrowserFillRequest(request.approvalId, null)
      return
    }
    const current = browserFill.value().request
    if (current?.approvalId === request.approvalId) return
    if (current) void resolveBrowserFillRequest(current.approvalId, null)
    browserFill.patch({ request, selectedId: request.candidates.length === 1 ? request.candidates[0].id : '', working: false })
  }

  async function syncPending() {
    if (previewMode || browserFill.value().syncWorking) return
    browserFill.patch({ syncWorking: true })
    try {
      const pending = await getPendingBrowserFill()
      const current = browserFill.value()
      browserFill.patch({ syncFailed: false })
      if (pending && current.request?.approvalId !== pending.approvalId) receive(pending)
      else if (!pending && current.request && !current.working) browserFill.patch({ request: null, selectedId: '' })
    } catch {
      if (!browserFill.value().syncFailed) {
        browserFill.patch({ syncFailed: true })
        void recordDiagnostic('browser_host', 'fill_listener_failed')
      }
    } finally {
      browserFill.patch({ syncWorking: false })
    }
  }

  function scheduleSync() {
    if (disposed) return
    syncTimer = window.setTimeout(() => {
      void syncPending().finally(scheduleSync)
    }, browserFill.value().request ? 500 : 3_000)
  }

  async function resolve(loginId: string | null, remember = false) {
    const current = browserFill.value()
    const request = current.request
    if (!request || current.working) return
    browserFill.patch({ working: true })
    try {
      await resolveBrowserFillRequest(request.approvalId, loginId, remember)
      if (loginId) {
        feedback.showNotice(
          'Login approved',
          remember
            ? `Filled one login for ${request.hostname}. This login fills there without asking for the next 15 minutes.`
            : `Filled one login for ${request.hostname}.`,
        )
      }
    } catch (error) {
      if (loginId) feedback.setError(error)
    } finally {
      if (browserFill.value().request?.approvalId === request.approvalId) browserFill.patch({ request: null, selectedId: '', remember: false })
      browserFill.patch({ working: false })
    }
  }

  return {
    receive,
    syncPending,
    resolve,
    clearSecrets() {
      const pending = browserFill.value().request
      if (pending) void resolveBrowserFillRequest(pending.approvalId, null)
      browserFill.patch({ request: null, selectedId: '', working: false, syncWorking: false })
    },
    start() {
      disposed = false
      if (previewMode) return () => {}
      void subscribeBrowserFill({
        request: (payload) => disposed ? void resolveBrowserFillRequest(payload.approvalId, null) : receive(payload),
        cancelled: (payload) => {
          if (browserFill.value().request?.approvalId === payload.approvalId) browserFill.patch({ request: null, selectedId: '', working: false })
        },
      }).then((stop) => {
        if (disposed) stop()
        else stopSubscription = stop
      }).catch(() => void recordDiagnostic('browser_host', 'fill_listener_failed'))
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
        const pending = browserFill.value().request
        if (pending) void resolveBrowserFillRequest(pending.approvalId, null)
      }
    },
  }
}

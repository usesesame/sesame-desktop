import type { AppStores } from '../stores/app-stores'
import type { BrowserTotpFillRequest } from '../types'
import {
  getPendingBrowserTotpFill,
  onVaultLocked,
  previewMode,
  recordDiagnostic,
  resolveBrowserTotpFill as resolveBrowserTotpFillRequest,
  subscribeBrowserTotpFill,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface TotpFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createTotpFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: TotpFillControllerOptions) {
  const { browserTotpFill } = stores
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: BrowserTotpFillRequest) {
    if (!request.candidates.length) {
      void resolveBrowserTotpFillRequest(request.approvalId, null)
      return
    }
    if (!modal.totpFillMayShow() || blockingOverlayActive()) {
      void resolveBrowserTotpFillRequest(request.approvalId, null)
      return
    }
    const current = browserTotpFill.value().request
    if (current?.approvalId === request.approvalId) return
    if (current) void resolveBrowserTotpFillRequest(current.approvalId, null)
    browserTotpFill.patch({ request, selectedId: request.candidates.length === 1 ? request.candidates[0].id : '', working: false })
  }

  async function syncPending() {
    if (previewMode || browserTotpFill.value().syncWorking) return
    browserTotpFill.patch({ syncWorking: true })
    try {
      const pending = await getPendingBrowserTotpFill()
      const current = browserTotpFill.value()
      browserTotpFill.patch({ syncFailed: false })
      if (pending && current.request?.approvalId !== pending.approvalId) receive(pending)
      else if (!pending && current.request && !current.working) browserTotpFill.patch({ request: null, selectedId: '' })
    } catch {
      if (!browserTotpFill.value().syncFailed) {
        browserTotpFill.patch({ syncFailed: true })
        void recordDiagnostic('browser_host', 'totp_fill_listener_failed')
      }
    } finally {
      browserTotpFill.patch({ syncWorking: false })
    }
  }

  function scheduleSync() {
    if (disposed) return
    syncTimer = window.setTimeout(() => {
      void syncPending().finally(scheduleSync)
    }, browserTotpFill.value().request ? 500 : 3_000)
  }

  async function resolve(loginId: string | null) {
    const current = browserTotpFill.value()
    const request = current.request
    if (!request || current.working) return
    browserTotpFill.patch({ working: true })
    try {
      await resolveBrowserTotpFillRequest(request.approvalId, loginId)
      if (loginId) feedback.showNotice('Code approved', `Filled a one-time code on ${request.hostname}.`)
    } catch (error) {
      if (loginId) feedback.setError(error)
    } finally {
      if (browserTotpFill.value().request?.approvalId === request.approvalId) browserTotpFill.patch({ request: null, selectedId: '' })
      browserTotpFill.patch({ working: false })
    }
  }

  return {
    receive,
    syncPending,
    resolve,
    clearSecrets() {
      const pending = browserTotpFill.value().request
      if (pending) void resolveBrowserTotpFillRequest(pending.approvalId, null)
      browserTotpFill.patch({ request: null, selectedId: '', working: false, syncWorking: false })
    },
    start() {
      disposed = false
      if (previewMode) return () => {}
      void subscribeBrowserTotpFill({
        request: (payload) => disposed ? void resolveBrowserTotpFillRequest(payload.approvalId, null) : receive(payload),
        cancelled: (payload) => {
          if (browserTotpFill.value().request?.approvalId === payload.approvalId) browserTotpFill.patch({ request: null, selectedId: '', working: false })
        },
      }).then((stop) => {
        if (disposed) stop()
        else stopSubscription = stop
      }).catch(() => void recordDiagnostic('browser_host', 'totp_fill_listener_failed'))
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
        const pending = browserTotpFill.value().request
        if (pending) void resolveBrowserTotpFillRequest(pending.approvalId, null)
      }
    },
  }
}

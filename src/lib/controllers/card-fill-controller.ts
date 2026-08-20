import type { AppStores } from '../stores/app-stores'
import type { BrowserCardFillRequest } from '../types'
import {
  getPendingBrowserCardFill,
  onVaultLocked,
  previewMode,
  recordDiagnostic,
  resolveBrowserCardFill as resolveBrowserCardFillRequest,
  subscribeBrowserCardFill,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface CardFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createCardFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: CardFillControllerOptions) {
  const { browserCardFill } = stores
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: BrowserCardFillRequest) {
    if (!request.candidates.length || !modal.cardFillMayShow() || blockingOverlayActive()) {
      void resolveBrowserCardFillRequest(request.approvalId, null)
      return
    }
    const current = browserCardFill.value().request
    if (current?.approvalId === request.approvalId) return
    if (current) void resolveBrowserCardFillRequest(current.approvalId, null)
    browserCardFill.patch({ request, selectedId: request.candidates.length === 1 ? request.candidates[0].id : '', working: false })
  }

  async function syncPending() {
    if (previewMode || browserCardFill.value().syncWorking) return
    browserCardFill.patch({ syncWorking: true })
    try {
      const pending = await getPendingBrowserCardFill()
      const current = browserCardFill.value()
      browserCardFill.patch({ syncFailed: false })
      if (pending && current.request?.approvalId !== pending.approvalId) receive(pending)
      else if (!pending && current.request && !current.working) browserCardFill.patch({ request: null, selectedId: '' })
    } catch {
      if (!browserCardFill.value().syncFailed) {
        browserCardFill.patch({ syncFailed: true })
        void recordDiagnostic('browser_host', 'card_fill_listener_failed')
      }
    } finally { browserCardFill.patch({ syncWorking: false }) }
  }

  function scheduleSync() {
    if (disposed) return
    syncTimer = window.setTimeout(() => { void syncPending().finally(scheduleSync) }, browserCardFill.value().request ? 500 : 3_000)
  }

  async function resolve(cardId: string | null) {
    const request = browserCardFill.value().request
    if (!request || browserCardFill.value().working) return
    browserCardFill.patch({ working: true })
    try {
      await resolveBrowserCardFillRequest(request.approvalId, cardId)
      if (cardId) feedback.showNotice('Card approved', `Filled card fields on ${request.hostname}.`)
    } catch (error) {
      if (cardId) feedback.setError(error)
    } finally {
      if (browserCardFill.value().request?.approvalId === request.approvalId) browserCardFill.patch({ request: null, selectedId: '' })
      browserCardFill.patch({ working: false })
    }
  }

  return {
    resolve,
    clearSecrets() {
      const request = browserCardFill.value().request
      if (request) void resolveBrowserCardFillRequest(request.approvalId, null)
      browserCardFill.patch({ request: null, selectedId: '', working: false, syncWorking: false })
    },
    start() {
      disposed = false
      if (previewMode) return () => {}
      void subscribeBrowserCardFill({
        request: (payload) => disposed ? void resolveBrowserCardFillRequest(payload.approvalId, null) : receive(payload),
        cancelled: (payload) => {
          if (browserCardFill.value().request?.approvalId === payload.approvalId) browserCardFill.patch({ request: null, selectedId: '', working: false })
        },
      }).then((stop) => { if (disposed) stop(); else stopSubscription = stop }).catch(() => void recordDiagnostic('browser_host', 'card_fill_listener_failed'))
      void onVaultLocked(() => { if (!disposed) handleVaultLocked() }).then((stop) => { if (disposed) stop(); else stopLockedListener = stop }).catch(() => void recordDiagnostic('renderer', 'vault_lock_listener_failed'))
      void syncPending()
      scheduleSync()
      return () => {
        disposed = true
        stopSubscription?.(); stopLockedListener?.()
        if (syncTimer) window.clearTimeout(syncTimer)
        const request = browserCardFill.value().request
        if (request) void resolveBrowserCardFillRequest(request.approvalId, null)
      }
    },
  }
}

import type { AppStores } from '../stores/app-stores'
import type { BrowserIdentityFillRequest } from '../types'
import {
  getPendingBrowserIdentityFill,
  onVaultLocked,
  previewMode,
  recordDiagnostic,
  resolveBrowserIdentityFill as resolveBrowserIdentityFillRequest,
  subscribeBrowserIdentityFill,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface IdentityFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createIdentityFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: IdentityFillControllerOptions) {
  const { browserIdentityFill } = stores
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: BrowserIdentityFillRequest) {
    if (!request.candidates.length) {
      void resolveBrowserIdentityFillRequest(request.approvalId, null)
      return
    }
    if (!modal.identityFillMayShow() || blockingOverlayActive()) {
      void resolveBrowserIdentityFillRequest(request.approvalId, null)
      return
    }
    const current = browserIdentityFill.value().request
    if (current?.approvalId === request.approvalId) return
    if (current) void resolveBrowserIdentityFillRequest(current.approvalId, null)
    browserIdentityFill.patch({ request, selectedId: request.candidates.length === 1 ? request.candidates[0].id : '', working: false })
  }

  async function syncPending() {
    if (previewMode || browserIdentityFill.value().syncWorking) return
    browserIdentityFill.patch({ syncWorking: true })
    try {
      const pending = await getPendingBrowserIdentityFill()
      const current = browserIdentityFill.value()
      browserIdentityFill.patch({ syncFailed: false })
      if (pending && current.request?.approvalId !== pending.approvalId) receive(pending)
      else if (!pending && current.request && !current.working) browserIdentityFill.patch({ request: null, selectedId: '' })
    } catch {
      if (!browserIdentityFill.value().syncFailed) {
        browserIdentityFill.patch({ syncFailed: true })
        void recordDiagnostic('browser_host', 'identity_fill_listener_failed')
      }
    } finally {
      browserIdentityFill.patch({ syncWorking: false })
    }
  }

  function scheduleSync() {
    if (disposed) return
    syncTimer = window.setTimeout(() => {
      void syncPending().finally(scheduleSync)
    }, browserIdentityFill.value().request ? 500 : 3_000)
  }

  async function resolve(identityId: string | null) {
    const current = browserIdentityFill.value()
    const request = current.request
    if (!request || current.working) return
    browserIdentityFill.patch({ working: true })
    try {
      await resolveBrowserIdentityFillRequest(request.approvalId, identityId)
      if (identityId) feedback.showNotice('Identity approved', `Filled fields on ${request.hostname}.`)
    } catch (error) {
      if (identityId) feedback.setError(error)
    } finally {
      if (browserIdentityFill.value().request?.approvalId === request.approvalId) browserIdentityFill.patch({ request: null, selectedId: '' })
      browserIdentityFill.patch({ working: false })
    }
  }

  return {
    receive,
    syncPending,
    resolve,
    clearSecrets() {
      const pending = browserIdentityFill.value().request
      if (pending) void resolveBrowserIdentityFillRequest(pending.approvalId, null)
      browserIdentityFill.patch({ request: null, selectedId: '', working: false, syncWorking: false })
    },
    start() {
      disposed = false
      if (previewMode) return () => {}
      void subscribeBrowserIdentityFill({
        request: (payload) => disposed ? void resolveBrowserIdentityFillRequest(payload.approvalId, null) : receive(payload),
        cancelled: (payload) => {
          if (browserIdentityFill.value().request?.approvalId === payload.approvalId) browserIdentityFill.patch({ request: null, selectedId: '', working: false })
        },
      }).then((stop) => {
        if (disposed) stop()
        else stopSubscription = stop
      }).catch(() => void recordDiagnostic('browser_host', 'identity_fill_listener_failed'))
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
        const pending = browserIdentityFill.value().request
        if (pending) void resolveBrowserIdentityFillRequest(pending.approvalId, null)
      }
    },
  }
}

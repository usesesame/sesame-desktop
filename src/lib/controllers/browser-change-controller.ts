import type { AppStores } from '../stores/app-stores'
import type { BrowserApprovalCancelled, BrowserChangeRequest, BrowserCreateRequest } from '../types'
import {
  getPendingBrowserChange,
  getPendingBrowserCreate,
  previewBrowserChangeRequest,
  previewBrowserCreateRequest,
  previewMode,
  recordDiagnostic,
  resolveBrowserChange,
  resolveBrowserCreate,
  subscribeBrowserChange,
  subscribeBrowserCreate,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface BrowserChangeControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  blockingOverlayActive: () => boolean
}

interface ApprovalStore<R> {
  value(): { request: R | null; selectedId: string; working: boolean; syncWorking: boolean; syncFailed: boolean }
  patch(values: Partial<{ request: R | null; selectedId: string; working: boolean; syncWorking: boolean; syncFailed: boolean }>): void
}

interface ApprovalFlow<R extends { approvalId: string }> {
  store: ApprovalStore<R>
  mayShow: () => boolean
  initialSelection: (request: R) => string
  decline: (approvalId: string) => Promise<void>
  pending: () => Promise<R | null>
  subscribe: (handlers: { request: (payload: R) => void; cancelled: (payload: BrowserApprovalCancelled) => void }) => Promise<() => void>
  preview: () => R | null
  listenerFailure: string
}

function approvalLoop<R extends { approvalId: string }>(flow: ApprovalFlow<R>, stores: AppStores, blockingOverlayActive: () => boolean) {
  const { store } = flow
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined

  function receive(request: R) {
    if (!flow.mayShow() || blockingOverlayActive()) {
      void flow.decline(request.approvalId)
      return
    }
    const current = store.value().request
    if (current?.approvalId === request.approvalId) return
    if (current) void flow.decline(current.approvalId)
    store.patch({ request, selectedId: flow.initialSelection(request), working: false })
  }

  async function syncPending() {
    if (previewMode || store.value().syncWorking) return
    store.patch({ syncWorking: true })
    try {
      const pending = await flow.pending()
      const current = store.value()
      store.patch({ syncFailed: false })
      if (pending && current.request?.approvalId !== pending.approvalId) receive(pending)
      else if (!pending && current.request && !current.working) store.patch({ request: null, selectedId: '' })
    } catch {
      if (!store.value().syncFailed) {
        store.patch({ syncFailed: true })
        void recordDiagnostic('browser_host', flow.listenerFailure)
      }
    } finally {
      store.patch({ syncWorking: false })
    }
  }

  function scheduleSync() {
    if (disposed) return
    syncTimer = window.setTimeout(() => {
      void syncPending().finally(scheduleSync)
    }, store.value().request ? 500 : 3_000)
  }

  function start() {
    disposed = false
    if (previewMode) {
      const preview = flow.preview()
      if (!preview) return () => {}
      const timer = window.setInterval(() => {
        if (!store.value().request && stores.vault.value().status.unlocked) receive(preview)
      }, 500)
      return () => window.clearInterval(timer)
    }
    void flow.subscribe({
      request: (payload) => (disposed ? void flow.decline(payload.approvalId) : receive(payload)),
      cancelled: (payload) => {
        if (store.value().request?.approvalId === payload.approvalId) store.patch({ request: null, selectedId: '', working: false })
      },
    }).then((stop) => {
      if (disposed) stop()
      else stopSubscription = stop
    }).catch(() => void recordDiagnostic('browser_host', flow.listenerFailure))
    void syncPending()
    scheduleSync()
    return () => {
      disposed = true
      stopSubscription?.()
      stopSubscription = undefined
      if (syncTimer) window.clearTimeout(syncTimer)
      syncTimer = undefined
      const pending = store.value().request
      if (pending) void flow.decline(pending.approvalId)
    }
  }

  function clearSecrets() {
    const pending = store.value().request
    if (pending) void flow.decline(pending.approvalId)
    store.patch({ request: null, selectedId: '', working: false, syncWorking: false })
  }

  return { receive, syncPending, start, clearSecrets }
}

export function createBrowserChangeController({ stores, feedback, modal, blockingOverlayActive }: BrowserChangeControllerOptions) {
  const store = stores.browserChange
  const loop = approvalLoop<BrowserChangeRequest>({
    store,
    mayShow: modal.browserChangeMayShow,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline: (approvalId) => resolveBrowserChange(approvalId, null),
    pending: getPendingBrowserChange,
    subscribe: subscribeBrowserChange,
    preview: previewBrowserChangeRequest,
    listenerFailure: 'change_listener_failed',
  }, stores, blockingOverlayActive)

  async function resolve(loginId: string | null) {
    const current = store.value()
    const request = current.request
    if (!request || current.working) return
    store.patch({ working: true })
    try {
      await resolveBrowserChange(request.approvalId, loginId)
    } catch (error) {
      if (loginId) feedback.setError(error)
    } finally {
      if (store.value().request?.approvalId === request.approvalId) store.patch({ request: null, selectedId: '' })
      store.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}

export function createBrowserCreateController({ stores, feedback, modal, blockingOverlayActive }: BrowserChangeControllerOptions) {
  const store = stores.browserCreate
  const loop = approvalLoop<BrowserCreateRequest>({
    store,
    mayShow: modal.browserCreateMayShow,
    initialSelection: () => '',
    decline: (approvalId) => resolveBrowserCreate(approvalId, false),
    pending: getPendingBrowserCreate,
    subscribe: subscribeBrowserCreate,
    preview: previewBrowserCreateRequest,
    listenerFailure: 'create_listener_failed',
  }, stores, blockingOverlayActive)

  async function resolve(approved: boolean) {
    const current = store.value()
    const request = current.request
    if (!request || current.working) return
    store.patch({ working: true })
    try {
      await resolveBrowserCreate(request.approvalId, approved)
    } catch (error) {
      if (approved) feedback.setError(error)
    } finally {
      if (store.value().request?.approvalId === request.approvalId) store.patch({ request: null, selectedId: '' })
      store.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}

import type { AppStores } from '../stores/app-stores'
import type { BrowserApprovalCancelled } from '../types'
import { onVaultLocked, previewMode, recordDiagnostic } from '../vault'

interface ApprovalStore<R> {
  value(): { request: R | null; selectedId: string; working: boolean; syncWorking: boolean; syncFailed: boolean }
  patch(values: Partial<{ request: R | null; selectedId: string; working: boolean; syncWorking: boolean; syncFailed: boolean }>): void
}

interface ApprovalFlow<R extends { approvalId: string }> {
  store: ApprovalStore<R>
  mayShow: () => boolean
  offersNothing?: (request: R) => boolean
  initialSelection: (request: R) => string
  decline: (approvalId: string) => Promise<void>
  pending: () => Promise<R | null>
  subscribe: (handlers: { request: (payload: R) => void; cancelled: (payload: BrowserApprovalCancelled) => void }) => Promise<() => void>
  preview: () => R | null
  listenerFailure: string
  onVaultLocked?: () => void
}

export function approvalLoop<R extends { approvalId: string }>(flow: ApprovalFlow<R>, stores: AppStores, blockingOverlayActive: () => boolean) {
  const { store } = flow
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: R) {
    if (flow.offersNothing?.(request) || !flow.mayShow() || blockingOverlayActive()) {
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
    const handleVaultLocked = flow.onVaultLocked
    if (handleVaultLocked) {
      void onVaultLocked(() => { if (!disposed) handleVaultLocked() }).then((stop) => {
        if (disposed) stop()
        else stopLockedListener = stop
      }).catch(() => void recordDiagnostic('renderer', 'vault_lock_listener_failed'))
    }
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

import type { AppStores } from '../stores/app-stores'
import type { BrowserApprovalCancelled } from '../types'
import { onVaultLocked, previewMode, recordDiagnostic } from '../vault'

interface ApprovalStore<R> {
  value(): { request: R | null; selectedId: string; working: boolean; syncWorking: boolean; syncFailed: boolean }
  patch(values: Partial<{ request: R | null; selectedId: string; working: boolean; syncWorking: boolean; syncFailed: boolean }>): void
}

interface ApprovalFlow<R extends { approvalId: string }, C extends { approvalId: string } = BrowserApprovalCancelled> {
  store: ApprovalStore<R>
  mayShow: () => boolean
  held?: () => boolean
  offersNothing?: (request: R) => boolean
  initialSelection: (request: R) => string
  decline: (approvalId: string) => Promise<void>
  pending: () => Promise<R | null>
  subscribe: (handlers: { request: (payload: R) => void; cancelled: (payload: C) => void }) => Promise<() => void>
  preview: () => R | null
  listenerFailure: string
  diagnosticOperation?: string
  onVaultLocked?: () => void
  onReplaced?: (current: R, next: R) => void
  onCancelled?: (payload: C) => void
  onVanished?: (current: R) => void
}

export function approvalLoop<R extends { approvalId: string }, C extends { approvalId: string } = BrowserApprovalCancelled>(flow: ApprovalFlow<R, C>, stores: AppStores, blockingOverlayActive: () => boolean) {
  const { store } = flow
  const diagnosticOperation = flow.diagnosticOperation ?? 'browser_host'
  let syncTimer: ReturnType<typeof window.setTimeout> | undefined
  let disposed = false
  let stopSubscription: (() => void) | undefined
  let stopLockedListener: (() => void) | undefined

  function receive(request: R) {
    if (flow.held?.()) return
    if (flow.offersNothing?.(request) || !flow.mayShow() || blockingOverlayActive()) {
      void flow.decline(request.approvalId)
      return
    }
    const current = store.value().request
    if (current?.approvalId === request.approvalId) return
    if (current && flow.onReplaced) {
      flow.onReplaced(current, request)
      return
    }
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
      else if (!pending && current.request && !current.working) {
        store.patch({ request: null, selectedId: '' })
        flow.onVanished?.(current.request)
      }
    } catch {
      if (!store.value().syncFailed) {
        store.patch({ syncFailed: true })
        void recordDiagnostic(diagnosticOperation, flow.listenerFailure)
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
        if (flow.onCancelled) flow.onCancelled(payload)
        else if (store.value().request?.approvalId === payload.approvalId) store.patch({ request: null, selectedId: '', working: false })
      },
    }).then((stop) => {
      if (disposed) stop()
      else stopSubscription = stop
    }).catch(() => void recordDiagnostic(diagnosticOperation, flow.listenerFailure))
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

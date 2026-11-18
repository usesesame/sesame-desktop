import type { AppStores, TerminalApprovalStoreState } from '../stores/app-stores'
import {
  getPendingTerminalRequest,
  previewTerminalRequest,
  previewTerminalUnlock,
  resolveTerminalRequest,
  subscribeTerminalApproval,
  subscribeTerminalUnlock,
  type CliApprovalCancelledEvent,
  type CliApprovalRequestEvent,
  type CliDecisionInput,
} from '../terminal-api'
import { cancelledLine, noticeOnly, secretNeeded } from '../terminal-text'
import { grantPresence, previewMode, recordDiagnostic } from '../vault'
import { approvalLoop } from './approval-loop'
import { messageFor, type FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

export const TOO_SOON_MESSAGE = 'Wait a moment after Sesame comes forward, then approve again.'
export const PRESENCE_NEEDED_MESSAGE = 'Enter your master password to send a hidden value.'
const NOTICE_TITLE = 'Terminal request closed'
const BROWSER_STORES = ['browserFill', 'browserIdentityFill', 'browserCardFill', 'browserTotpFill', 'browserSave', 'browserChange', 'browserCreate'] as const
const REMEMBERED_CANCELLATIONS = 32

interface TerminalApprovalControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  blockingOverlayActive: () => boolean
  presenceOpen: () => boolean
  overlayOpen?: () => boolean
}

type Patch = Partial<TerminalApprovalStoreState>

function freshFields(request: CliApprovalRequestEvent | null): Patch {
  return {
    selectedId: request && request.candidates.length === 1 ? request.candidates[0].id : '',
    allowTerminal: false,
    secret: '',
    presenceGranted: false,
    error: '',
    expiresAt: request ? Date.now() + request.expiresInMs : 0,
    working: false,
  }
}

export function createTerminalApprovalController({ stores, feedback, modal, blockingOverlayActive, presenceOpen, overlayOpen = () => false }: TerminalApprovalControllerOptions) {
  const store = stores.terminalApproval
  let closedQuietly: string | null = null
  let reported: string | null = null
  const ended: string[] = []
  const settling = new Set<string>()

  function rememberEnded(approvalId: string) {
    if (ended.includes(approvalId)) return
    ended.push(approvalId)
    if (ended.length > REMEMBERED_CANCELLATIONS) ended.shift()
  }

  function settled(approvalId: string): boolean {
    return ended.includes(approvalId) || settling.has(approvalId)
  }

  let backendDeadline: { approvalId: string; at: number } | null = null

  function keepBackendDeadline(pending: CliApprovalRequestEvent | null, askedAt: number) {
    if (!pending || store.value().request?.approvalId !== pending.approvalId) return
    const at = askedAt + pending.expiresInMs
    const known = backendDeadline?.approvalId === pending.approvalId ? backendDeadline.at : null
    if (known !== null && known >= at) return
    backendDeadline = { approvalId: pending.approvalId, at }
    store.patch({ expiresAt: at })
  }

  async function readBackendDeadline() {
    const askedAt = Date.now()
    try {
      keepBackendDeadline(await getPendingTerminalRequest(), askedAt)
    } catch {
      return
    }
  }

  const loopStore = {
    value: store.value,
    patch(values: Patch) {
      if ('request' in values && values.request?.approvalId !== store.value().request?.approvalId) {
        store.patch({ ...values, ...freshFields(values.request ?? null) })
        if (values.request && !previewMode) void readBackendDeadline()
      } else {
        store.patch(values)
      }
    },
  }

  function report(approvalId: string, reason: string) {
    if (reported === approvalId) return
    reported = approvalId
    if (closedQuietly === approvalId) closedQuietly = null
    feedback.showRefusal(NOTICE_TITLE, cancelledLine(reason))
  }

  function closeQuietly(approvalId: string) {
    if (store.value().request?.approvalId !== approvalId) return
    closedQuietly = approvalId
    loopStore.patch({ request: null })
  }

  async function decline(approvalId: string) {
    try {
      await resolveTerminalRequest({ approvalId, decision: 'deny' })
    } catch {
      return
    }
  }

  async function pendingNow(): Promise<CliApprovalRequestEvent | null> {
    const before = store.value().request?.approvalId
    const askedAt = Date.now()
    const pending = await getPendingTerminalRequest()
    const shown = store.value().request
    keepBackendDeadline(pending, askedAt)
    if (pending && settled(pending.approvalId)) return shown
    if (!pending && shown && shown.approvalId !== before) return shown
    return pending
  }

  async function confirmPending() {
    let pending: CliApprovalRequestEvent | null
    try {
      pending = await getPendingTerminalRequest()
    } catch {
      return
    }
    if (pending && !settled(pending.approvalId) && !store.value().request) loop.receive(pending)
  }

  async function reopenIfStillWaiting(approvalId: string, message: string) {
    let pending: CliApprovalRequestEvent | null
    try {
      pending = await getPendingTerminalRequest()
    } catch {
      feedback.showRefusal(NOTICE_TITLE, message)
      return
    }
    if (!pending || pending.approvalId !== approvalId || settled(approvalId) || store.value().request) return
    loop.receive(pending)
    if (store.value().request?.approvalId === approvalId) store.patch({ error: message })
  }

  async function closeWith(request: CliApprovalRequestEvent, decision: 'deny' | 'dismiss') {
    loopStore.patch({ request: null })
    settling.add(request.approvalId)
    try {
      await resolveTerminalRequest({ approvalId: request.approvalId, decision })
    } catch (error) {
      settling.delete(request.approvalId)
      await reopenIfStillWaiting(request.approvalId, messageFor(error))
      return
    }
    settling.delete(request.approvalId)
    rememberEnded(request.approvalId)
  }

  const loop = approvalLoop<CliApprovalRequestEvent, CliApprovalCancelledEvent>({
    store: loopStore,
    mayShow: () => modal.terminalMayShow() && !presenceOpen(),
    held: overlayOpen,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline,
    pending: pendingNow,
    subscribe: subscribeTerminalApproval,
    preview: previewTerminalRequest,
    listenerFailure: 'terminal_listener_failed',
    diagnosticOperation: 'renderer',
    onVaultLocked: () => {
      const current = store.value().request
      if (current) closeQuietly(current.approvalId)
      store.patch({ secret: '' })
    },
    onReplaced: (current) => {
      closeQuietly(current.approvalId)
      void confirmPending()
    },
    onCancelled: (payload) => {
      rememberEnded(payload.approvalId)
      const current = store.value().request
      if (current?.approvalId === payload.approvalId) {
        loopStore.patch({ request: null })
        report(payload.approvalId, payload.reason)
      } else if (closedQuietly === payload.approvalId) {
        report(payload.approvalId, payload.reason)
      }
    },
    onVanished: (current) => {
      closedQuietly = current.approvalId
    },
  }, stores, blockingOverlayActive)

  function offered(request: CliApprovalRequestEvent, itemId: string): boolean {
    return request.candidates.some((candidate) => candidate.id === itemId)
  }

  function finish(approvalId: string) {
    if (store.value().request?.approvalId === approvalId) loopStore.patch({ request: null })
  }

  async function send(request: CliApprovalRequestEvent, decision: CliDecisionInput): Promise<boolean> {
    try {
      await resolveTerminalRequest(decision)
      return true
    } catch (error) {
      const message = messageFor(error)
      if (message === TOO_SOON_MESSAGE && store.value().request?.approvalId === request.approvalId) {
        store.patch({ working: false, error: message })
        return false
      }
      if (message === PRESENCE_NEEDED_MESSAGE && store.value().request?.approvalId === request.approvalId) {
        store.patch({ working: false, error: message, presenceGranted: false, request: { ...request, needsPresence: true } })
        return false
      }
      finish(request.approvalId)
      reported = request.approvalId
      feedback.showRefusal(NOTICE_TITLE, message)
      return false
    }
  }

  async function allow() {
    const state = store.value()
    const request = state.request
    if (!request || state.working) return
    if (noticeOnly(request)) return dismiss()
    const itemId = state.selectedId
    if (request.candidates.length > 1 && !offered(request, itemId)) {
      store.patch({ error: 'Choose one of the items Sesame offered.' })
      return
    }
    if (itemId && !offered(request, itemId)) {
      store.patch({ error: 'Choose one of the items Sesame offered.' })
      return
    }
    const needsSecret = secretNeeded(request, itemId, state.presenceGranted)
    if (needsSecret && !state.secret) {
      store.patch({ error: PRESENCE_NEEDED_MESSAGE })
      return
    }
    const secret = state.secret
    store.patch({ working: true, error: '', secret: '' })
    if (needsSecret) {
      try {
        await grantPresence(secret)
      } catch (error) {
        if (store.value().request?.approvalId === request.approvalId) store.patch({ working: false, error: messageFor(error) })
        return
      }
      if (store.value().request?.approvalId === request.approvalId) store.patch({ presenceGranted: true })
    }
    if (store.value().request?.approvalId !== request.approvalId) return
    const decision: CliDecisionInput = { approvalId: request.approvalId, decision: 'allow' }
    if (itemId) decision.itemId = itemId
    if (request.canAllowTerminal && state.allowTerminal === true) decision.allowTerminal = true
    if (request.copy) decision.clearAfterSeconds = stores.settings.value().clipboardClearSeconds
    if (await send(request, decision)) {
      rememberEnded(request.approvalId)
      finish(request.approvalId)
    }
  }

  async function deny() {
    const state = store.value()
    const request = state.request
    if (!request) return
    if (noticeOnly(request)) return dismiss()
    await closeWith(request, 'deny')
  }

  async function dismiss() {
    const request = store.value().request
    if (!request) return
    await closeWith(request, 'dismiss')
  }

  function expire(approvalId: string) {
    if (store.value().request?.approvalId !== approvalId) return
    loopStore.patch({ request: null })
    report(approvalId, 'expired')
  }

  function setAside() {
    const current = store.value().request
    if (current && !store.value().working) closeQuietly(current.approvalId)
  }

  function select(itemId: string) {
    const request = store.value().request
    if (!request || store.value().working || !offered(request, itemId)) return
    store.patch({ selectedId: itemId, error: '' })
  }

  function setAllowTerminal(checked: boolean) {
    const request = store.value().request
    store.patch({ allowTerminal: Boolean(request?.canAllowTerminal) && checked })
  }

  function setSecret(secret: string) {
    store.patch({ secret, error: '' })
  }

  function start() {
    const stopLoop = loop.start()
    const stopBrowserWatch = BROWSER_STORES.map((name) => stores[name].subscribe((state: { request: unknown }) => {
      const current = store.value().request
      if (state.request && current) closeQuietly(current.approvalId)
    }))
    const stopUnlockedWatch = stores.vault.subscribe((state) => {
      if (state.status.unlocked && store.value().unlock) store.patch({ unlock: null })
    })
    let disposed = false
    let stopUnlock: () => void = () => {}
    if (previewMode) {
      const preview = previewTerminalUnlock()
      if (preview && !stores.vault.value().status.unlocked) store.patch({ unlock: preview })
    } else {
      void subscribeTerminalUnlock({
        request: (payload) => { if (!stores.vault.value().status.unlocked) store.patch({ unlock: payload }) },
        ended: () => store.patch({ unlock: null }),
      }).then((stop) => {
        if (disposed) stop()
        else stopUnlock = stop
      }).catch(() => {
        store.patch({ unlock: null })
        void recordDiagnostic('renderer', 'terminal_listener_failed')
      })
    }
    return () => {
      disposed = true
      stopLoop()
      stopUnlock()
      for (const stop of stopBrowserWatch) stop()
      stopUnlockedWatch()
    }
  }

  function clearSecrets() {
    const current = store.value().request
    if (current) closedQuietly = current.approvalId
    store.patch({ ...freshFields(null), request: null, syncWorking: false, unlock: store.value().unlock })
  }

  return { receive: loop.receive, syncPending: loop.syncPending, start, clearSecrets, setAside, allow, deny, dismiss, expire, select, setAllowTerminal, setSecret }
}

export type TerminalApprovalController = ReturnType<typeof createTerminalApprovalController>

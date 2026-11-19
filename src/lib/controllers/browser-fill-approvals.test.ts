// @vitest-environment jsdom
import { writable } from 'svelte/store'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import { claimPromptSurface, createApprovalGate } from './approval-gate'
import { createBrowserFillController } from './browser-fill-controller'
import { createCardFillController } from './card-fill-controller'
import { createFeedbackController } from './feedback-controller'
import { createIdentityFillController } from './identity-fill-controller'
import { createModalController } from './modal-controller'
import { createTotpFillController } from './totp-fill-controller'

const vaultApi = vi.hoisted(() => ({
  getPendingBrowserFill: vi.fn(),
  getPendingBrowserIdentityFill: vi.fn(),
  getPendingBrowserCardFill: vi.fn(),
  getPendingBrowserTotpFill: vi.fn(),
  onVaultLocked: vi.fn(),
  recordDiagnostic: vi.fn(),
  resolveBrowserFill: vi.fn(),
  resolveBrowserIdentityFill: vi.fn(),
  resolveBrowserCardFill: vi.fn(),
  resolveBrowserTotpFill: vi.fn(),
  subscribeBrowserFill: vi.fn(),
  subscribeBrowserIdentityFill: vi.fn(),
  subscribeBrowserCardFill: vi.fn(),
  subscribeBrowserTotpFill: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  ...vaultApi,
}))

vi.mock('../release-record-api', () => ({
  previewBrowserFillRequest: vi.fn(() => null),
}))

type Stores = ReturnType<typeof createAppStores>
type StoreName = 'browserFill' | 'browserIdentityFill' | 'browserCardFill' | 'browserTotpFill'
type Options = Parameters<typeof createBrowserFillController>[0]
type Controller = { resolve: (id: string | null) => Promise<void>; clearSecrets: () => void; start: () => () => void }

interface Flow {
  name: string
  create: (options: Options) => Controller
  store: StoreName
  subscribe: Mock
  pending: Mock
  answer: Mock
  failure: string
  notice: string
}

const flows: Flow[] = [
  { name: 'login fill', create: createBrowserFillController, store: 'browserFill', subscribe: vaultApi.subscribeBrowserFill, pending: vaultApi.getPendingBrowserFill, answer: vaultApi.resolveBrowserFill, failure: 'fill_listener_failed', notice: 'Login approved' },
  { name: 'identity fill', create: createIdentityFillController, store: 'browserIdentityFill', subscribe: vaultApi.subscribeBrowserIdentityFill, pending: vaultApi.getPendingBrowserIdentityFill, answer: vaultApi.resolveBrowserIdentityFill, failure: 'identity_fill_listener_failed', notice: 'Identity approved' },
  { name: 'card fill', create: createCardFillController, store: 'browserCardFill', subscribe: vaultApi.subscribeBrowserCardFill, pending: vaultApi.getPendingBrowserCardFill, answer: vaultApi.resolveBrowserCardFill, failure: 'card_fill_listener_failed', notice: 'Card approved' },
  { name: 'one-time code fill', create: createTotpFillController, store: 'browserTotpFill', subscribe: vaultApi.subscribeBrowserTotpFill, pending: vaultApi.getPendingBrowserTotpFill, answer: vaultApi.resolveBrowserTotpFill, failure: 'totp_fill_listener_failed', notice: 'Code approved' },
]

function request(approvalId: string, candidates = ['candidate-a']) {
  return {
    approvalId,
    origin: 'https://shop.example.test',
    hostname: 'shop.example.test',
    requestedFields: [],
    candidates: candidates.map((id) => ({ id, title: `Fictional ${id}` })),
    expiresInSeconds: 30,
    expiresAtUnixMs: 1_900_000_000_000,
  } as never
}

function deferred() {
  let settle: (value?: unknown) => void = () => {}
  let fail: (reason: unknown) => void = () => {}
  const promise = new Promise((resolve, reject) => {
    settle = resolve
    fail = reject
  })
  return { promise, settle, fail }
}

const flush = () => vi.advanceTimersByTimeAsync(0)

describe.each(flows)('$name approvals', (flow) => {
  let stores: Stores
  let feedback: ReturnType<typeof createFeedbackController>
  let handleLocked: Mock
  let overlay: boolean
  let handlers: { request: (payload: unknown) => void; cancelled: (payload: unknown) => void }
  let lockHandler: () => void
  let stopSubscription: Mock
  let stopLocked: Mock

  beforeEach(() => {
    vi.useFakeTimers()
    for (const mock of Object.values(vaultApi)) mock.mockReset()
    stores = createAppStores()
    stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: true } })
    feedback = createFeedbackController()
    vi.spyOn(feedback, 'showNotice')
    vi.spyOn(feedback, 'setError')
    handleLocked = vi.fn()
    overlay = false
    stopSubscription = vi.fn()
    stopLocked = vi.fn()
    flow.subscribe.mockImplementation(async (next) => {
      handlers = next
      return stopSubscription
    })
    vaultApi.onVaultLocked.mockImplementation(async (next) => {
      lockHandler = next
      return stopLocked
    })
    flow.pending.mockResolvedValue(null)
    flow.answer.mockResolvedValue(undefined)
    vaultApi.recordDiagnostic.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function state() {
    return stores[flow.store].value()
  }

  async function started() {
    const modal = createModalController({ stores, feedback })
    const controller = flow.create({ stores, feedback, onVaultLocked: handleLocked, modal, blockingOverlayActive: () => overlay })
    const stop = controller.start()
    await flush()
    return { controller, stop, modal }
  }

  it('listens for requests and the lock before the first poll', async () => {
    const { stop } = await started()
    expect(flow.subscribe).toHaveBeenCalledTimes(1)
    expect(vaultApi.onVaultLocked).toHaveBeenCalledTimes(1)
    expect(flow.pending).toHaveBeenCalledTimes(1)
    expect(flow.subscribe.mock.invocationCallOrder[0]).toBeLessThan(vaultApi.onVaultLocked.mock.invocationCallOrder[0])
    expect(vaultApi.onVaultLocked.mock.invocationCallOrder[0]).toBeLessThan(flow.pending.mock.invocationCallOrder[0])
    stop()
  })

  it('shows a request and preselects a single candidate only', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    expect(state()).toMatchObject({ selectedId: 'candidate-a', working: false })
    expect(state().request?.approvalId).toBe('approval-1')
    handlers.request(request('approval-2', ['candidate-a', 'candidate-b']))
    expect(state().selectedId).toBe('')
    stop()
  })

  it('declines a request with no candidates without showing it', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1', []))
    expect(state().request).toBeNull()
    expect(flow.answer).toHaveBeenCalledWith('approval-1', null)
    stop()
  })

  it('declines a request while a blocking overlay or another browser approval is open', async () => {
    const { stop } = await started()
    overlay = true
    handlers.request(request('approval-1'))
    expect(flow.answer).toHaveBeenLastCalledWith('approval-1', null)
    overlay = false
    const other = flow.store === 'browserFill' ? 'browserTotpFill' : 'browserFill'
    stores[other].patch({ request: request('other-approval') })
    handlers.request(request('approval-2'))
    expect(flow.answer).toHaveBeenLastCalledWith('approval-2', null)
    expect(state().request).toBeNull()
    stop()
  })

  it('ignores a replay of the approval it already shows', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    handlers.request(request('approval-1'))
    flow.pending.mockResolvedValue(request('approval-1'))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().request?.approvalId).toBe('approval-1')
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })

  it('declines a replayed request that arrives after it stopped', async () => {
    const { stop } = await started()
    stop()
    handlers.request(request('approval-1'))
    expect(state().request).toBeNull()
    expect(flow.answer).toHaveBeenCalledWith('approval-1', null)
  })

  it('keeps the shown request when a cancellation names a stale approval id', async () => {
    const { stop } = await started()
    handlers.request(request('approval-2'))
    handlers.cancelled({ approvalId: 'approval-1', reason: 'expired' })
    expect(state().request?.approvalId).toBe('approval-2')
    stop()
  })

  it('declines the stale approval when a newer one arrives', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    handlers.request(request('approval-2'))
    expect(flow.answer).toHaveBeenCalledWith('approval-1', null)
    expect(state().request?.approvalId).toBe('approval-2')
    flow.pending.mockResolvedValue(request('approval-3'))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(flow.answer).toHaveBeenCalledWith('approval-2', null)
    expect(state().request?.approvalId).toBe('approval-3')
    stop()
  })

  it('does not close a newer request when a stale answer finishes', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    const answer = deferred()
    flow.answer.mockReturnValueOnce(answer.promise)
    const resolving = controller.resolve('candidate-a')
    expect(state().working).toBe(true)
    handlers.request(request('approval-2'))
    expect(flow.answer).toHaveBeenCalledWith('approval-1', null)
    answer.settle()
    await resolving
    expect(state().request?.approvalId).toBe('approval-2')
    expect(state().working).toBe(false)
    stop()
  })

  it('answers once and ignores a second answer while the first is in flight', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    const answer = deferred()
    flow.answer.mockReturnValueOnce(answer.promise)
    const first = controller.resolve('candidate-a')
    await controller.resolve('candidate-a')
    answer.settle()
    await first
    expect(flow.answer).toHaveBeenCalledTimes(1)
    expect(flow.answer).toHaveBeenCalledWith('approval-1', 'candidate-a')
    expect(feedback.showNotice).toHaveBeenCalledWith(flow.notice, expect.stringContaining('shop.example.test'))
    expect(state()).toMatchObject({ request: null, selectedId: '', working: false })
    stop()
  })

  it('shows an error when approving fails but not when declining fails', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    flow.answer.mockRejectedValueOnce(new Error('fictional failure'))
    await controller.resolve(null)
    expect(feedback.setError).not.toHaveBeenCalled()
    handlers.request(request('approval-2'))
    flow.answer.mockRejectedValueOnce(new Error('fictional failure'))
    await controller.resolve('candidate-a')
    expect(feedback.setError).toHaveBeenCalledTimes(1)
    expect(feedback.showNotice).not.toHaveBeenCalled()
    expect(state()).toMatchObject({ request: null, working: false })
    stop()
  })

  it('closes a cancelled approval without answering it', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    handlers.cancelled({ approvalId: 'approval-1', reason: 'denied' })
    expect(state()).toMatchObject({ request: null, selectedId: '', working: false })
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })

  it('closes a cancelled approval even while its answer is in flight', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    const answer = deferred()
    flow.answer.mockReturnValueOnce(answer.promise)
    const resolving = controller.resolve('candidate-a')
    handlers.cancelled({ approvalId: 'approval-1', reason: 'connectionClosed' })
    expect(state()).toMatchObject({ request: null, working: false })
    answer.settle()
    await resolving
    expect(state()).toMatchObject({ request: null, working: false })
    stop()
  })

  it('drops a request the desktop no longer holds unless an answer is in flight', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    const answer = deferred()
    flow.answer.mockReturnValueOnce(answer.promise)
    const resolving = controller.resolve('candidate-a')
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().request?.approvalId).toBe('approval-1')
    answer.settle()
    await resolving
    handlers.request(request('approval-2'))
    await vi.advanceTimersByTimeAsync(500)
    expect(state()).toMatchObject({ request: null, selectedId: '' })
    stop()
  })

  it('polls every 3 seconds when idle and every half second while a request is shown', async () => {
    const { stop } = await started()
    await vi.advanceTimersByTimeAsync(2_999)
    expect(flow.pending).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(flow.pending).toHaveBeenCalledTimes(2)
    flow.pending.mockResolvedValue(request('approval-1'))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(flow.pending).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(500)
    expect(flow.pending).toHaveBeenCalledTimes(4)
    stop()
    await vi.advanceTimersByTimeAsync(10_000)
    expect(flow.pending).toHaveBeenCalledTimes(4)
  })

  it('reports a failing poll once until a poll succeeds again', async () => {
    flow.pending.mockRejectedValue(new Error('fictional failure'))
    const { stop } = await started()
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state()).toMatchObject({ syncFailed: true, syncWorking: false })
    expect(vaultApi.recordDiagnostic).toHaveBeenCalledTimes(1)
    expect(vaultApi.recordDiagnostic).toHaveBeenCalledWith('browser_host', flow.failure)
    flow.pending.mockResolvedValue(null)
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().syncFailed).toBe(false)
    flow.pending.mockRejectedValue(new Error('fictional failure'))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(vaultApi.recordDiagnostic).toHaveBeenCalledTimes(2)
    stop()
  })

  it('reports listener failures under their own names', async () => {
    flow.subscribe.mockRejectedValue(new Error('fictional failure'))
    vaultApi.onVaultLocked.mockRejectedValue(new Error('fictional failure'))
    const { stop } = await started()
    expect(vaultApi.recordDiagnostic).toHaveBeenCalledWith('browser_host', flow.failure)
    expect(vaultApi.recordDiagnostic).toHaveBeenCalledWith('renderer', 'vault_lock_listener_failed')
    stop()
  })

  it('passes a lock during approval to the app and declines the approval when the app clears secrets', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    lockHandler()
    expect(handleLocked).toHaveBeenCalledTimes(1)
    controller.clearSecrets()
    expect(flow.answer).toHaveBeenCalledWith('approval-1', null)
    expect(state()).toMatchObject({ request: null, selectedId: '', working: false, syncWorking: false })
    stop()
    expect(flow.answer).toHaveBeenCalledTimes(1)
  })

  it('declines an approval whose answer is in flight when the vault locks', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    const answer = deferred()
    flow.answer.mockReturnValueOnce(answer.promise)
    const resolving = controller.resolve('candidate-a')
    lockHandler()
    controller.clearSecrets()
    expect(flow.answer).toHaveBeenLastCalledWith('approval-1', null)
    expect(state()).toMatchObject({ request: null, working: false })
    answer.settle()
    await resolving
    expect(state()).toMatchObject({ request: null, working: false })
    stop()
  })

  it('stops listening and declines what is shown when it stops', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    stop()
    expect(stopSubscription).toHaveBeenCalledTimes(1)
    expect(stopLocked).toHaveBeenCalledTimes(1)
    expect(flow.answer).toHaveBeenCalledWith('approval-1', null)
    lockHandler()
    expect(handleLocked).not.toHaveBeenCalled()
  })

  it('releases listeners that register only after it stopped', async () => {
    const subscription = deferred()
    const locked = deferred()
    flow.subscribe.mockReturnValue(subscription.promise)
    vaultApi.onVaultLocked.mockReturnValue(locked.promise)
    const { stop } = await started()
    stop()
    subscription.settle(stopSubscription)
    locked.settle(stopLocked)
    await flush()
    expect(stopSubscription).toHaveBeenCalledTimes(1)
    expect(stopLocked).toHaveBeenCalledTimes(1)
  })
})

describe.each(flows)('$name approvals behind something the person is answering', (flow) => {
  let stores: Stores
  let feedback: ReturnType<typeof createFeedbackController>
  let handlers: { request: (payload: unknown) => void; cancelled: (payload: unknown) => void }
  let answering: ReturnType<typeof writable<boolean>>

  beforeEach(() => {
    vi.useFakeTimers()
    for (const mock of Object.values(vaultApi)) mock.mockReset()
    stores = createAppStores()
    stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: true } })
    feedback = createFeedbackController()
    answering = writable(false)
    flow.subscribe.mockImplementation(async (next) => {
      handlers = next
      return () => {}
    })
    vaultApi.onVaultLocked.mockImplementation(async () => () => {})
    flow.pending.mockResolvedValue(null)
    flow.answer.mockResolvedValue(undefined)
    vaultApi.recordDiagnostic.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function state() {
    return stores[flow.store].value()
  }

  async function started() {
    const modal = createModalController({ stores, feedback })
    const gate = createApprovalGate(stores, answering)
    const controller = flow.create({ stores, feedback, onVaultLocked: vi.fn(), modal, held: () => gate.held(flow.store) }) as Controller & { syncPending: () => Promise<void> }
    const stopWake = gate.whenClear(() => void controller.syncPending())
    const stopLoop = controller.start()
    await flush()
    return { controller, modal, stop: () => { stopWake(); stopLoop() } }
  }

  it('waits unanswered while the person answers something else and shows as soon as the way is clear', async () => {
    const { stop } = await started()
    answering.set(true)
    flow.pending.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    await vi.advanceTimersByTimeAsync(9_000)
    expect(state().request).toBeNull()
    expect(flow.answer).not.toHaveBeenCalled()
    answering.set(false)
    await flush()
    expect(state().request?.approvalId).toBe('approval-1')
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })

  it('waits behind an open dialog or menu instead of turning the request down', async () => {
    const { modal, stop } = await started()
    expect(modal.open({ kind: 'login-editor' })).toBe(true)
    answering.set(true)
    const releaseMenu = claimPromptSurface()
    flow.pending.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    modal.close()
    answering.set(false)
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().request).toBeNull()
    releaseMenu()
    await flush()
    expect(state().request?.approvalId).toBe('approval-1')
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })

  it('waits behind a terminal approval or another browser approval and never declines either', async () => {
    const { stop } = await started()
    const other = flow.store === 'browserFill' ? 'browserTotpFill' : 'browserFill'
    stores[other].patch({ request: request('other-approval') })
    flow.pending.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    expect(state().request).toBeNull()
    stores[other].patch({ request: null })
    await flush()
    expect(state().request?.approvalId).toBe('approval-1')
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })

  it('lets a waiting request expire by its own deadline without an answer from the window', async () => {
    const { stop } = await started()
    answering.set(true)
    flow.pending.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    await vi.advanceTimersByTimeAsync(27_000)
    flow.pending.mockResolvedValue(null)
    handlers.cancelled({ approvalId: 'approval-1', reason: 'expired' })
    await vi.advanceTimersByTimeAsync(6_000)
    answering.set(false)
    await flush()
    expect(state().request).toBeNull()
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })

  it('still ignores a replay and still closes on a cancellation once a waiting request is shown', async () => {
    const { stop } = await started()
    answering.set(true)
    flow.pending.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    answering.set(false)
    await flush()
    handlers.request(request('approval-1'))
    expect(state().request?.approvalId).toBe('approval-1')
    handlers.cancelled({ approvalId: 'stale-approval', reason: 'expired' })
    expect(state().request?.approvalId).toBe('approval-1')
    handlers.cancelled({ approvalId: 'approval-1', reason: 'connectionClosed' })
    expect(state().request).toBeNull()
    expect(flow.answer).not.toHaveBeenCalled()
    stop()
  })
})

// @vitest-environment jsdom
import { get, writable } from 'svelte/store'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import { approvalOnScreen, claimApprovalSurface, claimPromptSurface, createApprovalGate, promptOnScreen } from './approval-gate'
import { createBrowserChangeController, createBrowserCreateController } from './browser-change-controller'
import { createBrowserSaveController } from './browser-save-controller'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  getPendingBrowserSave: vi.fn(),
  getPendingBrowserChange: vi.fn(),
  getPendingBrowserCreate: vi.fn(),
  neverSaveBrowserSite: vi.fn(),
  onVaultLocked: vi.fn(),
  recordDiagnostic: vi.fn(),
  resolveBrowserSave: vi.fn(),
  resolveBrowserChange: vi.fn(),
  resolveBrowserCreate: vi.fn(),
  subscribeBrowserSave: vi.fn(),
  subscribeBrowserChange: vi.fn(),
  subscribeBrowserCreate: vi.fn(),
  previewBrowserChangeRequest: vi.fn(() => null),
  previewBrowserCreateRequest: vi.fn(() => null),
}))

vi.mock('../vault', () => ({ previewMode: false, ...vaultApi }))

const flush = () => vi.advanceTimersByTimeAsync(0)

function request(approvalId: string) {
  return {
    approvalId,
    origin: 'https://shop.example.test',
    hostname: 'shop.example.test',
    kind: 'new',
    title: 'shop.example.test',
    username: 'casey@example.test',
    candidates: [{ id: 'candidate-a', title: 'Fictional candidate', username: '', email: '', savedOrigin: 'https://shop.example.test', matchKind: 'exact' }],
    style: 'characters',
    size: 20,
    expiresInSeconds: 30,
    expiresAtUnixMs: 1_900_000_000_000,
  } as never
}

describe('the approval gate', () => {
  it('holds every approval while something the person is answering is open and wakes once when it closes', () => {
    const stores = createAppStores()
    const answering = writable(false)
    const gate = createApprovalGate(stores, answering)
    const wake = vi.fn()
    const stop = gate.whenClear(wake)
    expect(wake).toHaveBeenCalledTimes(1)
    expect(gate.held('browserFill')).toBe(false)
    answering.set(true)
    expect(gate.held('browserFill')).toBe(true)
    expect(gate.held('terminalApproval')).toBe(true)
    answering.set(false)
    expect(wake).toHaveBeenCalledTimes(2)
    const release = claimPromptSurface()
    expect(gate.held('browserSave')).toBe(true)
    release()
    release()
    expect(get(promptOnScreen)).toBe(false)
    expect(wake).toHaveBeenCalledTimes(3)
    stop()
  })

  it('holds an approval while another kind is showing but not behind its own request', () => {
    const stores = createAppStores()
    const gate = createApprovalGate(stores, writable(false))
    stores.terminalApproval.patch({ request: { approvalId: 'terminal-1' } as never })
    expect(gate.held('browserFill')).toBe(true)
    expect(gate.held('terminalApproval')).toBe(false)
    stores.terminalApproval.patch({ request: null })
    stores.browserFill.patch({ request: request('browser-1') })
    expect(gate.held('terminalApproval')).toBe(true)
    expect(gate.held('browserFill')).toBe(false)
  })

  it('counts approvals on screen apart from other dialogs', () => {
    const release = claimApprovalSurface()
    expect(get(approvalOnScreen)).toBe(true)
    expect(get(promptOnScreen)).toBe(false)
    release()
    expect(get(approvalOnScreen)).toBe(false)
  })
})

type Kind = 'browserSave' | 'browserChange' | 'browserCreate'

interface Flow {
  name: string
  store: Kind
  subscribe: Mock
  pending: Mock
  answer: Mock
  create: (options: never) => { start: () => () => void; syncPending: () => Promise<void> }
}

const flows: Flow[] = [
  { name: 'save', store: 'browserSave', subscribe: vaultApi.subscribeBrowserSave, pending: vaultApi.getPendingBrowserSave, answer: vaultApi.resolveBrowserSave, create: createBrowserSaveController as never },
  { name: 'change', store: 'browserChange', subscribe: vaultApi.subscribeBrowserChange, pending: vaultApi.getPendingBrowserChange, answer: vaultApi.resolveBrowserChange, create: createBrowserChangeController as never },
  { name: 'create', store: 'browserCreate', subscribe: vaultApi.subscribeBrowserCreate, pending: vaultApi.getPendingBrowserCreate, answer: vaultApi.resolveBrowserCreate, create: createBrowserCreateController as never },
]

describe.each(flows)('browser $name approvals behind something the person is answering', (flow) => {
  let handlers: { request: (payload: unknown) => void }

  beforeEach(() => {
    vi.useFakeTimers()
    for (const mock of Object.values(vaultApi)) mock.mockReset()
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

  it('waits unanswered and shows once the way is clear', async () => {
    const stores = createAppStores()
    const feedback = createFeedbackController()
    const modal = createModalController({ stores, feedback })
    const answering = writable(true)
    const gate = createApprovalGate(stores, answering)
    const controller = flow.create({ stores, feedback, modal, onVaultLocked: vi.fn(), held: () => gate.held(flow.store) } as never)
    const stopWake = gate.whenClear(() => void controller.syncPending())
    const stop = controller.start()
    await flush()
    flow.pending.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    await vi.advanceTimersByTimeAsync(6_000)
    expect(stores[flow.store].value().request).toBeNull()
    answering.set(false)
    await flush()
    expect(stores[flow.store].value().request).toMatchObject({ approvalId: 'approval-1' })
    expect(flow.answer).not.toHaveBeenCalled()
    stopWake()
    stop()
  })
})

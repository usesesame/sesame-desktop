// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { CliApprovalRequestEvent } from '../terminal-api'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'
import { createTerminalApprovalController, PRESENCE_NEEDED_MESSAGE, TOO_SOON_MESSAGE } from './terminal-approval-controller'

const terminalApi = vi.hoisted(() => ({
  getPendingTerminalRequest: vi.fn(),
  resolveTerminalRequest: vi.fn(),
  subscribeTerminalApproval: vi.fn(),
  subscribeTerminalUnlock: vi.fn(),
  previewTerminalRequest: vi.fn(() => null),
  previewTerminalUnlock: vi.fn(() => null),
}))

const vaultApi = vi.hoisted(() => ({
  grantPresence: vi.fn(),
  onVaultLocked: vi.fn(),
  recordDiagnostic: vi.fn(),
}))

vi.mock('../terminal-api', () => terminalApi)
vi.mock('../vault', () => ({ previewMode: false, ...vaultApi }))

function request(approvalId: string, partial: Partial<CliApprovalRequestEvent> = {}): CliApprovalRequestEvent {
  return {
    approvalId,
    command: 'get',
    field: 'password',
    fieldHidden: true,
    copy: false,
    candidates: [{ id: 'northwind', kind: 'login', title: 'Northwind mail', fieldHidden: false }],
    terminal: 'pts/3',
    program: { reportedName: 'bash' },
    remote: false,
    canAllowTerminal: true,
    needsPresence: false,
    missingField: false,
    allowed: false,
    expiresInMs: 60_000,
    ...partial,
  }
}

const flush = () => vi.advanceTimersByTimeAsync(0)

describe('terminal approvals in the window', () => {
  let stores: ReturnType<typeof createAppStores>
  let feedback: ReturnType<typeof createFeedbackController>
  let handlers: { request: (payload: CliApprovalRequestEvent) => void; cancelled: (payload: { approvalId: string; reason: string }) => void }
  let unlockHandlers: { request: (payload: unknown) => void; ended: (payload: unknown) => void }
  let lockHandler: () => void
  let presenceOpen: boolean

  beforeEach(() => {
    vi.useFakeTimers()
    for (const mock of [...Object.values(terminalApi), ...Object.values(vaultApi)]) mock.mockReset()
    stores = createAppStores()
    stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: true } })
    feedback = createFeedbackController()
    vi.spyOn(feedback, 'showRefusal')
    presenceOpen = false
    onboarding = false
    terminalApi.subscribeTerminalApproval.mockImplementation(async (next) => {
      handlers = next
      return () => {}
    })
    terminalApi.subscribeTerminalUnlock.mockImplementation(async (next) => {
      unlockHandlers = next
      return () => {}
    })
    vaultApi.onVaultLocked.mockImplementation(async (next) => {
      lockHandler = next
      return () => {}
    })
    terminalApi.getPendingTerminalRequest.mockResolvedValue(null)
    terminalApi.resolveTerminalRequest.mockResolvedValue(undefined)
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.recordDiagnostic.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function state() {
    return stores.terminalApproval.value()
  }

  let onboarding: boolean

  async function started() {
    const modal = createModalController({ stores, feedback })
    const controller = createTerminalApprovalController({ stores, feedback, modal, blockingOverlayActive: () => onboarding, presenceOpen: () => presenceOpen, overlayOpen: () => onboarding })
    const stop = controller.start()
    await flush()
    return { controller, stop, modal }
  }

  function decisions() {
    return terminalApi.resolveTerminalRequest.mock.calls.map(([decision]) => decision)
  }

  it('shows a request with its single item chosen and the terminal box off', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    expect(state()).toMatchObject({ selectedId: 'northwind', allowTerminal: false, secret: '', working: false })
    expect(state().request?.approvalId).toBe('approval-1')
    stop()
  })

  it('sends allowTerminal only when the box was ticked on a request that offers it', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    await controller.allow()
    expect(decisions()[0]).toEqual({ approvalId: 'approval-1', decision: 'allow', itemId: 'northwind' })

    handlers.request(request('approval-2', { canAllowTerminal: false }))
    controller.setAllowTerminal(true)
    expect(state().allowTerminal).toBe(false)
    await controller.allow()
    expect(decisions()[1]).not.toHaveProperty('allowTerminal')

    handlers.request(request('approval-3'))
    controller.setAllowTerminal(true)
    await controller.allow()
    expect(decisions()[2]).toEqual({ approvalId: 'approval-3', decision: 'allow', itemId: 'northwind', allowTerminal: true })
    stop()
  })

  it('starts every request with the box off even after the last one ticked it', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    controller.setAllowTerminal(true)
    await controller.deny()
    handlers.request(request('approval-2'))
    expect(state().allowTerminal).toBe(false)
    stop()
  })

  it('refuses to send an item that the chooser did not offer', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', {
      candidates: [
        { id: 'northwind-a', kind: 'login', title: 'Northwind mail', fieldHidden: false },
        { id: 'northwind-b', kind: 'login', title: 'Northwind mail', fieldHidden: false },
      ],
    }))
    expect(state().selectedId).toBe('')
    await controller.allow()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    controller.select('contoso-bank')
    expect(state().selectedId).toBe('')
    stores.terminalApproval.patch({ selectedId: 'contoso-bank' })
    await controller.allow()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    expect(state().error).toBe('Choose one of the items Sesame offered.')
    controller.select('northwind-b')
    await controller.allow()
    expect(decisions()).toEqual([{ approvalId: 'approval-1', decision: 'allow', itemId: 'northwind-b' }])
    stop()
  })

  it('ignores a replay of the request it already shows and keeps what the person chose', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    controller.setAllowTerminal(true)
    handlers.request(request('approval-1', { candidates: [{ id: 'contoso', kind: 'login', title: 'Contoso bank', fieldHidden: false }] }))
    expect(state().allowTerminal).toBe(true)
    expect(state().request?.candidates[0].id).toBe('northwind')
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('never swaps a second request into the dialog and shows only what Sesame still holds', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    controller.setAllowTerminal(true)
    controller.setSecret('fictional-master-password')
    const second = request('approval-2', { candidates: [{ id: 'contoso', kind: 'login', title: 'Contoso bank', fieldHidden: false }] })
    terminalApi.getPendingTerminalRequest.mockResolvedValue(second)
    handlers.request(second)
    expect(state().request).toBeNull()
    expect(state().secret).toBe('')
    await flush()
    expect(state().request?.approvalId).toBe('approval-2')
    expect(state()).toMatchObject({ allowTerminal: false, secret: '', selectedId: 'contoso' })
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('drops a stray request that Sesame no longer holds', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    terminalApi.getPendingTerminalRequest.mockResolvedValue(null)
    handlers.request(request('approval-0'))
    await flush()
    expect(state().request).toBeNull()
    stop()
  })

  it('keeps the dialog when a cancellation names another approval and closes it with a reason for its own', async () => {
    const { stop } = await started()
    handlers.request(request('approval-2'))
    handlers.cancelled({ approvalId: 'approval-1', reason: 'expired' })
    expect(state().request?.approvalId).toBe('approval-2')
    expect(feedback.showRefusal).not.toHaveBeenCalled()

    handlers.cancelled({ approvalId: 'approval-2', reason: 'connectionClosed' })
    expect(state().request).toBeNull()
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', 'The terminal stopped waiting, so Sesame closed its request.')

    handlers.cancelled({ approvalId: 'approval-2', reason: 'connectionClosed' })
    expect(feedback.showRefusal).toHaveBeenCalledTimes(1)
    stop()
  })

  it('sends nothing for an approval after its cancellation arrived', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    handlers.cancelled({ approvalId: 'approval-1', reason: 'expired' })
    await controller.allow()
    await controller.deny()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('closes with the reason Sesame gives when an approval id is no longer waiting', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error('This terminal request is no longer waiting in Sesame.'))
    await controller.allow()
    expect(state().request).toBeNull()
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', 'This terminal request is no longer waiting in Sesame.')
    handlers.cancelled({ approvalId: 'approval-1', reason: 'vaultChanged' })
    expect(feedback.showRefusal).toHaveBeenCalledTimes(1)
    stop()
  })

  it('keeps the dialog open when Sesame says the approval came too soon', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error(TOO_SOON_MESSAGE))
    await controller.allow()
    expect(state().request?.approvalId).toBe('approval-1')
    expect(state()).toMatchObject({ working: false, error: TOO_SOON_MESSAGE })
    stop()
  })

  it('checks the master password before it allows a hidden value and never asks twice', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', { needsPresence: true }))
    await controller.allow()
    expect(vaultApi.grantPresence).not.toHaveBeenCalled()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()

    vaultApi.grantPresence.mockRejectedValueOnce(new Error('That master password is not right.'))
    controller.setSecret('fictional-wrong-password')
    await controller.allow()
    expect(state()).toMatchObject({ secret: '', error: 'That master password is not right.', working: false })
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()

    controller.setSecret('fictional-master-password')
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error(TOO_SOON_MESSAGE))
    await controller.allow()
    expect(vaultApi.grantPresence).toHaveBeenLastCalledWith('fictional-master-password')
    expect(state()).toMatchObject({ presenceGranted: true, secret: '' })

    await controller.allow()
    expect(vaultApi.grantPresence).toHaveBeenCalledTimes(2)
    expect(decisions().at(-1)).toEqual({ approvalId: 'approval-1', decision: 'allow', itemId: 'northwind' })
    expect(state().request).toBeNull()
    stop()
  })

  it('asks for the master password only when the chosen item sends a hidden value', async () => {
    const { controller, stop } = await started()
    const candidates = [
      { id: 'northwind', kind: 'login', title: 'Northwind mail', fieldName: 'Recovery PIN', fieldHidden: true },
      { id: 'contoso', kind: 'login', title: 'Northwind mail', fieldName: 'Member number', fieldHidden: false },
    ]
    handlers.request(request('approval-1', { field: 'field:0', needsPresence: true, candidates }))
    controller.select('contoso')
    await controller.allow()
    expect(vaultApi.grantPresence).not.toHaveBeenCalled()
    expect(decisions()[0]).toEqual({ approvalId: 'approval-1', decision: 'allow', itemId: 'contoso' })

    handlers.request(request('approval-2', { field: 'field:0', needsPresence: true, candidates }))
    controller.select('northwind')
    await controller.allow()
    expect(state().error).toBe('Enter your master password to send a hidden value.')
    expect(decisions()).toHaveLength(1)
    stop()
  })

  it('does not allow a request that changed while the master password was checked', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', { needsPresence: true }))
    controller.setSecret('fictional-master-password')
    let finishPresence: () => void = () => {}
    vaultApi.grantPresence.mockReturnValueOnce(new Promise<void>((resolve) => { finishPresence = resolve }))
    const allowing = controller.allow()
    terminalApi.getPendingTerminalRequest.mockResolvedValue(request('approval-2'))
    handlers.request(request('approval-2'))
    await flush()
    finishPresence()
    await allowing
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    expect(state().request?.approvalId).toBe('approval-2')
    stop()
  })

  it('closes the dialog and forgets the password when the vault locks', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', { needsPresence: true }))
    controller.setSecret('fictional-master-password')
    lockHandler()
    expect(state()).toMatchObject({ request: null, secret: '' })
    handlers.cancelled({ approvalId: 'approval-1', reason: 'vaultChanged' })
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', 'The vault locked or changed, so Sesame closed the terminal request.')
    await controller.allow()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('counts down to the deadline Sesame holds, not the one the event carried when it was sent', async () => {
    const { stop } = await started()
    terminalApi.getPendingTerminalRequest.mockResolvedValue(request('approval-1', { expiresInMs: 54_000 }))
    handlers.request(request('approval-1', { expiresInMs: 60_000 }))
    await flush()
    expect(state().expiresAt - Date.now()).toBe(54_000)

    terminalApi.getPendingTerminalRequest.mockResolvedValue(request('approval-1', { expiresInMs: 52_000 }))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().expiresAt - Date.now()).toBe(52_000)

    stop()
  })

  it('turns Allow and Deny into a dismissal for a field the item does not have', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', { field: 'Recovery PIN', fieldHidden: false, missingField: true, canAllowTerminal: false }))
    await controller.allow()
    handlers.request(request('approval-2', { field: 'Recovery PIN', fieldHidden: false, missingField: true, canAllowTerminal: false }))
    await controller.deny()
    expect(decisions()).toEqual([
      { approvalId: 'approval-1', decision: 'dismiss' },
      { approvalId: 'approval-2', decision: 'dismiss' },
    ])
    stop()
  })

  it('waits behind onboarding instead of opening over it or turning the request down', async () => {
    const { stop } = await started()
    onboarding = true
    terminalApi.getPendingTerminalRequest.mockResolvedValue(request('approval-1'))
    handlers.request(request('approval-1'))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().request).toBeNull()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()

    onboarding = false
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().request?.approvalId).toBe('approval-1')

    onboarding = true
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().request?.approvalId).toBe('approval-1')
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('counts the time a reading took and never lets an older reading push the deadline later', async () => {
    const { stop } = await started()
    let answer: (value: CliApprovalRequestEvent) => void = () => {}
    terminalApi.getPendingTerminalRequest.mockReturnValueOnce(new Promise((resolve) => { answer = resolve }))
    const asked = Date.now()
    handlers.request(request('approval-1', { expiresInMs: 60_000 }))
    await vi.advanceTimersByTimeAsync(2_000)
    answer(request('approval-1', { expiresInMs: 10_000 }))
    await flush()
    expect(state().expiresAt).toBe(asked + 10_000)

    terminalApi.getPendingTerminalRequest.mockResolvedValue(request('approval-1', { expiresInMs: 4_000 }))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(state().expiresAt).toBe(asked + 10_000)
    stop()
  })

  it('leaves a waiting request to the lock instead of denying it', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', { needsPresence: true }))
    controller.setSecret('fictional-master-password')
    controller.clearSecrets()
    expect(state()).toMatchObject({ request: null, secret: '' })
    await flush()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    handlers.cancelled({ approvalId: 'approval-1', reason: 'vaultChanged' })
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', 'The vault locked or changed, so Sesame closed the terminal request.')
    stop()
  })

  it('gives way to a browser request at once and says why when Sesame reports the preemption', async () => {
    const { stop } = await started()
    handlers.request(request('approval-1'))
    stores.browserFill.patch({ request: { approvalId: 'browser-1', origin: 'https://northwind.example', hostname: 'northwind.example', candidates: [], expiresInSeconds: 30, expiresAtUnixMs: 0 } })
    expect(state().request).toBeNull()
    expect(stores.browserFill.value().request?.approvalId).toBe('browser-1')
    handlers.cancelled({ approvalId: 'approval-1', reason: 'preempted' })
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', expect.stringContaining('A browser request needed the window'))
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('turns a request down while a browser approval, a modal or the password prompt is open', async () => {
    const { modal, stop } = await started()
    stores.browserFill.patch({ request: { approvalId: 'browser-1', origin: 'https://northwind.example', hostname: 'northwind.example', candidates: [], expiresInSeconds: 30, expiresAtUnixMs: 0 } })
    handlers.request(request('approval-1'))
    expect(state().request).toBeNull()
    stores.browserFill.patch({ request: null })
    modal.open({ kind: 'import' })
    handlers.request(request('approval-2'))
    modal.close()
    presenceOpen = true
    handlers.request(request('approval-3'))
    expect(state().request).toBeNull()
    expect(decisions()).toEqual([
      { approvalId: 'approval-1', decision: 'deny' },
      { approvalId: 'approval-2', decision: 'deny' },
      { approvalId: 'approval-3', decision: 'deny' },
    ])
    stop()
  })

  it('keeps other modals from opening over a terminal approval', async () => {
    const { modal, stop } = await started()
    handlers.request(request('approval-1'))
    expect(modal.open({ kind: 'import' })).toBe(false)
    expect(modal.open({ kind: 'login-editor' })).toBe(false)
    expect(modal.state.value().active).toBeNull()
    stop()
  })

  it('answers a request for a missing item only with dismiss', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1', { candidates: [], notFound: 'Northwnd mail', canAllowTerminal: false }))
    expect(state().request?.approvalId).toBe('approval-1')
    await controller.allow()
    expect(decisions()).toEqual([{ approvalId: 'approval-1', decision: 'dismiss' }])
    handlers.request(request('approval-2', { candidates: [], notFound: 'Northwnd mail', canAllowTerminal: false }))
    await controller.deny()
    expect(decisions()[1]).toEqual({ approvalId: 'approval-2', decision: 'dismiss' })
    stop()
  })

  it('closes on expiry with a line that says so and sends nothing afterwards', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    controller.expire('approval-0')
    expect(state().request?.approvalId).toBe('approval-1')
    controller.expire('approval-1')
    expect(state().request).toBeNull()
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', 'The terminal request was not answered in time, so Sesame turned it down.')
    handlers.cancelled({ approvalId: 'approval-1', reason: 'expired' })
    expect(feedback.showRefusal).toHaveBeenCalledTimes(1)
    await controller.allow()
    expect(terminalApi.resolveTerminalRequest).not.toHaveBeenCalled()
    stop()
  })

  it('passes the clipboard clearing time only for a copy', async () => {
    const { controller, stop } = await started()
    stores.settings.patch({ clipboardClearSeconds: 10 })
    handlers.request(request('approval-1', { copy: true }))
    await controller.allow()
    expect(decisions()[0]).toEqual({ approvalId: 'approval-1', decision: 'allow', itemId: 'northwind', clearAfterSeconds: 10 })
    stop()
  })

  it('shows the unlock notice while locked and clears it when the wait ends', async () => {
    stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: false } })
    const { stop } = await started()
    unlockHandlers.request({ command: 'totp', terminal: 'pts/3', remote: false })
    expect(state().unlock).toMatchObject({ command: 'totp' })
    unlockHandlers.ended({ reason: 'expired' })
    expect(state().unlock).toBeNull()
    unlockHandlers.request({ command: 'list', remote: true })
    stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: true } })
    expect(state().unlock).toBeNull()
    stop()
  })

  it('leaves a newer approval working when an older decision comes back', async () => {
    const { controller, stop } = await started()
    let answerFirst: () => void = () => {}
    terminalApi.resolveTerminalRequest.mockReturnValueOnce(new Promise<void>((resolve) => { answerFirst = resolve }))
    handlers.request(request('approval-1'))
    const first = controller.allow()
    handlers.cancelled({ approvalId: 'approval-1', reason: 'expired' })
    handlers.request(request('approval-2'))
    let answerSecond: () => void = () => {}
    terminalApi.resolveTerminalRequest.mockReturnValueOnce(new Promise<void>((resolve) => { answerSecond = resolve }))
    const second = controller.allow()
    expect(state()).toMatchObject({ working: true })
    answerFirst()
    await first
    expect(state().request?.approvalId).toBe('approval-2')
    expect(state().working).toBe(true)
    answerSecond()
    await second
    expect(state().request).toBeNull()
    stop()
  })

  it.each(['deny', 'dismiss'] as const)('shows the error and the request again when %s did not reach Sesame', async (decision) => {
    const { controller, stop } = await started()
    const shown = decision === 'deny' ? request('approval-1') : request('approval-1', { candidates: [], notFound: 'Northwnd mail', canAllowTerminal: false })
    handlers.request(shown)
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error('Sesame could not reach the request.'))
    terminalApi.getPendingTerminalRequest.mockResolvedValueOnce(shown)
    await (decision === 'deny' ? controller.deny() : controller.dismiss())
    expect(state().request?.approvalId).toBe('approval-1')
    expect(state().error).toBe('Sesame could not reach the request.')

    await (decision === 'deny' ? controller.deny() : controller.dismiss())
    expect(decisions().at(-1)).toEqual({ approvalId: 'approval-1', decision })
    expect(state().request).toBeNull()
    stop()
  })

  it('keeps a request closed when its failed denial finds it already gone or replaced', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error('Sesame could not reach the request.'))
    terminalApi.getPendingTerminalRequest.mockResolvedValueOnce(request('approval-3'))
    await controller.deny()
    expect(state().request).toBeNull()
    expect(state().error).toBe('')
    stop()
  })

  it('does not show a request again when its cancellation arrived while a poll was out', async () => {
    const { stop } = await started()
    let answerPoll: (value: CliApprovalRequestEvent) => void = () => {}
    terminalApi.getPendingTerminalRequest.mockReturnValueOnce(new Promise((resolve) => { answerPoll = resolve }))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(terminalApi.getPendingTerminalRequest).toHaveBeenCalledTimes(2)
    handlers.cancelled({ approvalId: 'approval-1', reason: 'connectionClosed' })
    answerPoll(request('approval-1'))
    await flush()
    expect(state().request).toBeNull()
    stop()
  })

  it('keeps a request closed when a poll that began before its denial returns it afterwards', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    let answerPoll: (value: CliApprovalRequestEvent) => void = () => {}
    terminalApi.getPendingTerminalRequest.mockReturnValueOnce(new Promise((resolve) => { answerPoll = resolve }))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(terminalApi.getPendingTerminalRequest).toHaveBeenCalledTimes(3)
    await controller.deny()
    answerPoll(request('approval-1'))
    await flush()
    expect(state().request).toBeNull()
    stop()
  })

  it('says a denial may not have reached Sesame when it cannot check the request', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error('Sesame could not reach the request.'))
    terminalApi.getPendingTerminalRequest.mockRejectedValueOnce(new Error('unreachable'))
    await controller.deny()
    expect(state().request).toBeNull()
    expect(feedback.showRefusal).toHaveBeenCalledWith('Terminal request closed', 'Sesame could not reach the request.')
    stop()
  })

  it('asks for the master password when Sesame says it lapsed and keeps the request', async () => {
    const { controller, stop } = await started()
    handlers.request(request('approval-1'))
    terminalApi.resolveTerminalRequest.mockRejectedValueOnce(new Error(PRESENCE_NEEDED_MESSAGE))
    await controller.allow()
    expect(state().request?.approvalId).toBe('approval-1')
    expect(state().request?.needsPresence).toBe(true)
    expect(state()).toMatchObject({ working: false, error: PRESENCE_NEEDED_MESSAGE })
    await controller.allow()
    expect(decisions()).toHaveLength(1)
    controller.setSecret('fictional-master-password')
    await controller.allow()
    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional-master-password')
    expect(decisions()).toHaveLength(2)
    stop()
  })

  it('clears the waiting terminal notice when the unlock listeners could not be set up', async () => {
    stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: false } })
    let fail: (error: Error) => void = () => {}
    terminalApi.subscribeTerminalUnlock.mockImplementation((next) => {
      unlockHandlers = next
      return new Promise((_, reject) => { fail = reject })
    })
    const { stop } = await started()
    unlockHandlers.request({ command: 'list', terminal: 'pts/3', remote: false })
    expect(state().unlock).not.toBeNull()
    fail(new Error('fictional listen failure'))
    await flush()
    expect(state().unlock).toBeNull()
    stop()
  })

  it('keeps a request it shows even when a poll that began before it reports nothing', async () => {
    const { stop } = await started()
    let answerPoll: (value: null) => void = () => {}
    terminalApi.getPendingTerminalRequest.mockReturnValueOnce(new Promise((resolve) => { answerPoll = resolve }))
    await vi.advanceTimersByTimeAsync(3_000)
    expect(terminalApi.getPendingTerminalRequest).toHaveBeenCalledTimes(2)
    handlers.request(request('approval-1'))
    answerPoll(null)
    await flush()
    expect(state().request?.approvalId).toBe('approval-1')
    stop()
  })
})

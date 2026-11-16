import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { BrowserChangeRequest, PendingChangeView, VaultSnapshot } from '../types'
import { createAppStores } from '../stores/app-stores'
import { createBrowserChangeController, createBrowserCreateController } from './browser-change-controller'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'
import { createPendingChangesController, pendingChangeMessage } from './pending-changes-controller'

const vaultApi = vi.hoisted(() => ({
  discardPendingLogin: vi.fn(),
  getPendingBrowserChange: vi.fn(),
  getPendingBrowserCreate: vi.fn(),
  goBackPendingChange: vi.fn(),
  keepPendingChange: vi.fn(),
  listPendingChanges: vi.fn(),
  onPendingChangesChanged: vi.fn(),
  previewBrowserChangeRequest: vi.fn(),
  previewBrowserCreateRequest: vi.fn(),
  recordDiagnostic: vi.fn(),
  resolveBrowserChange: vi.fn(),
  resolveBrowserCreate: vi.fn(),
  subscribeBrowserChange: vi.fn(),
  subscribeBrowserCreate: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  ...vaultApi,
}))

function view(partial: Partial<PendingChangeView>): PendingChangeView {
  return {
    id: 'change-1',
    itemId: 'login-a',
    kind: 'change',
    host: 'example.com',
    title: 'Northwind',
    username: 'casey@example.com',
    createdAt: 1,
    fill: 'unknown',
    accepted: false,
    canGoBack: true,
    daysLeft: 30,
    urgent: false,
    ...partial,
  }
}

const SNAPSHOT = { revision: 2, entries: [], folders: [] } as unknown as VaultSnapshot

function plain(text: string) {
  expect(text).not.toMatch(/[—–()]/)
  expect(text.split('. ').length).toBeLessThanOrEqual(2)
  expect(text.endsWith('.')).toBe(true)
}

describe('pending password notices', () => {
  it('say what happened and what to do in at most two plain sentences', () => {
    const cases = [
      view({}),
      view({ fill: 'notFilled' }),
      view({ urgent: true, daysLeft: 6 }),
      view({ urgent: true, daysLeft: 1 }),
      view({ canGoBack: false, daysLeft: undefined }),
      view({ kind: 'new', username: '' }),
      view({ kind: 'new', username: 'casey@example.com' }),
    ]
    for (const change of cases) plain(pendingChangeMessage(change))
  })

  it('suggests going back when the browser could not fill the new password', () => {
    expect(pendingChangeMessage(view({ fill: 'notFilled' }))).toBe('The browser could not fill the new password for Northwind. Go back to the old password.')
  })

  it('warns from day 23 how long the old password stays in history', () => {
    expect(pendingChangeMessage(view({ urgent: true, daysLeft: 6 }))).toBe('The new password for Northwind is still not confirmed. The old one leaves history in 6 days.')
    expect(pendingChangeMessage(view({ urgent: true, daysLeft: 1 }))).toContain('in 1 day.')
  })

  it('shows the username a sign up attached', () => {
    expect(pendingChangeMessage(view({ kind: 'new', username: 'casey@example.com' }))).toContain('as casey@example.com')
  })
})

describe('pending password controller', () => {
  beforeEach(() => {
    for (const mock of Object.values(vaultApi)) mock.mockReset()
  })

  it('applies the list the desktop returns after going back and keeps nothing else', async () => {
    const stores = createAppStores()
    stores.vault.patch({ snapshot: SNAPSHOT })
    const change = view({})
    stores.pendingChanges.patch({ changes: [change] })
    vaultApi.goBackPendingChange.mockResolvedValue({ changes: [], snapshot: { ...SNAPSHOT, revision: 3 } })
    const controller = createPendingChangesController({ stores, feedback: createFeedbackController(), editLogin: vi.fn(), copyPassword: vi.fn() })

    await controller.goBack(change)

    expect(vaultApi.goBackPendingChange).toHaveBeenCalledWith('change-1')
    expect(stores.pendingChanges.value().changes).toEqual([])
    expect(stores.vault.value().snapshot?.revision).toBe(3)
    expect(stores.pendingChanges.value().working).toBeNull()
  })

  it('keeps the notice when the desktop refuses', async () => {
    const stores = createAppStores()
    const change = view({})
    stores.pendingChanges.patch({ changes: [change] })
    vaultApi.keepPendingChange.mockRejectedValue(new Error('This password is no longer waiting.'))
    const feedback = createFeedbackController()
    const controller = createPendingChangesController({ stores, feedback, editLogin: vi.fn(), copyPassword: vi.fn() })

    await controller.keep(change)

    expect(stores.pendingChanges.value().changes).toEqual([change])
  })

  it('copies through the guarded login copy and never reads the password itself', async () => {
    const stores = createAppStores()
    const copyPassword = vi.fn().mockResolvedValue(undefined)
    const controller = createPendingChangesController({ stores, feedback: createFeedbackController(), editLogin: vi.fn(), copyPassword })
    await controller.copy(view({}))
    expect(copyPassword).toHaveBeenCalledWith('login-a')
  })
})

describe('change and create approvals', () => {
  beforeEach(() => {
    for (const mock of Object.values(vaultApi)) mock.mockReset()
    vaultApi.resolveBrowserChange.mockResolvedValue(undefined)
    vaultApi.resolveBrowserCreate.mockResolvedValue(undefined)
  })

  function changeRequest(): BrowserChangeRequest {
    return {
      approvalId: 'approval-1',
      origin: 'https://example.com',
      hostname: 'example.com',
      candidates: [{ id: 'login-a', title: 'Northwind', username: 'casey@example.com', email: '', savedOrigin: 'https://example.com', matchKind: 'exact' }],
      unconfirmed: [],
      expiresInSeconds: 30,
      expiresAtUnixMs: Date.now() + 30_000,
    }
  }

  it('declines a change request while another browser approval is open', () => {
    const stores = createAppStores()
    const feedback = createFeedbackController()
    const modal = createModalController({ stores, feedback })
    stores.browserSave.patch({ request: { approvalId: 'save-1' } as never })
    const controller = createBrowserChangeController({ stores, feedback, modal, blockingOverlayActive: () => false })

    controller.receive(changeRequest())

    expect(stores.browserChange.value().request).toBeNull()
    expect(vaultApi.resolveBrowserChange).toHaveBeenCalledWith('approval-1', null)
  })

  it('selects the only offered login and sends that choice', async () => {
    const stores = createAppStores()
    const feedback = createFeedbackController()
    const modal = createModalController({ stores, feedback })
    const controller = createBrowserChangeController({ stores, feedback, modal, blockingOverlayActive: () => false })

    controller.receive(changeRequest())
    expect(stores.browserChange.value().selectedId).toBe('login-a')
    await controller.resolve(stores.browserChange.value().selectedId)

    expect(vaultApi.resolveBrowserChange).toHaveBeenCalledWith('approval-1', 'login-a')
    expect(stores.browserChange.value().request).toBeNull()
  })

  it('a create request blocks other modals until it is answered', async () => {
    const stores = createAppStores()
    const feedback = createFeedbackController()
    const modal = createModalController({ stores, feedback })
    const controller = createBrowserCreateController({ stores, feedback, modal, blockingOverlayActive: () => false })

    controller.receive({ approvalId: 'approval-2', origin: 'https://example.com', hostname: 'example.com', expiresInSeconds: 30, expiresAtUnixMs: Date.now() + 30_000 })
    expect(modal.browserFillMayShow()).toBe(false)
    await controller.resolve(false)

    expect(vaultApi.resolveBrowserCreate).toHaveBeenCalledWith('approval-2', false)
    expect(modal.browserFillMayShow()).toBe(true)
  })
})

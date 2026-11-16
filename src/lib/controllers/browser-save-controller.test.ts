import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { BrowserSaveRequest, VaultSnapshot } from '../types'
import { get } from 'svelte/store'
import { neverSaveSites } from '../never-save-sites'
import { createAppStores } from '../stores/app-stores'
import { createBrowserSaveController } from './browser-save-controller'
import { createFeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  getPendingBrowserSave: vi.fn(),
  neverSaveBrowserSite: vi.fn(),
  onVaultLocked: vi.fn(),
  recordDiagnostic: vi.fn(),
  resolveBrowserSave: vi.fn(),
  subscribeBrowserSave: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  ...vaultApi,
}))

function snapshotWith(issueKinds: string[]): VaultSnapshot {
  return { entries: [{ id: 'login-a', issueKinds }], folders: [] } as unknown as VaultSnapshot
}

function request(kind: 'new' | 'update'): BrowserSaveRequest {
  return {
    approvalId: 'approval-1',
    origin: 'https://example.test',
    hostname: 'example.test',
    kind,
    title: 'example.test',
    username: '',
    candidates: [{
      id: 'login-a',
      title: 'Fictional Account',
      username: 'casey@example.test',
      email: '',
      savedOrigin: 'https://example.test',
      matchKind: 'exact',
    }],
    expiresInSeconds: 30,
    expiresAtUnixMs: Date.now() + 30_000,
  }
}

function harness(activeItemId: string) {
  const stores = createAppStores()
  stores.selection.patch({ activeItemId, activeItemKind: 'login', securityFilter: 'old-password' })
  const feedback = createFeedbackController()
  const modal = { browserSaveMayShow: () => true } as unknown as ModalController
  const controller = createBrowserSaveController({
    stores,
    feedback,
    onVaultLocked: vi.fn(),
    modal,
    blockingOverlayActive: () => false,
  })
  return { stores, feedback, controller }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('browser save notices', () => {
  it('clears the security filter when the update resolves the active login issue', async () => {
    const resolved = snapshotWith(['totp'])
    vaultApi.resolveBrowserSave.mockResolvedValue({ id: 'login-a', snapshot: resolved })
    const { stores, controller } = harness('login-a')
    controller.receive(request('update'))

    await controller.resolve(true)

    expect(stores.selection.value().securityFilter).toBeNull()
    expect(stores.vault.value().snapshot).toBe(resolved)
  })

  it('keeps the security filter when the active login still has the issue', async () => {
    vaultApi.resolveBrowserSave.mockResolvedValue({ id: 'login-a', snapshot: snapshotWith(['old-password']) })
    const { stores, controller } = harness('login-a')
    controller.receive(request('update'))

    await controller.resolve(true)

    expect(stores.selection.value().securityFilter).toBe('old-password')
  })

  it('keeps the security filter when another login is active', async () => {
    vaultApi.resolveBrowserSave.mockResolvedValue({ id: 'login-a', snapshot: snapshotWith(['totp']) })
    const { stores, controller } = harness('login-b')
    controller.receive(request('update'))

    await controller.resolve(true)

    expect(stores.selection.value().securityFilter).toBe('old-password')
  })

  it('keeps the filter when the update is declined', async () => {
    const { stores, controller } = harness('login-a')
    controller.receive(request('update'))

    await controller.resolve(false)

    expect(stores.selection.value().securityFilter).toBe('old-password')
    expect(stores.vault.value().snapshot).toBeNull()
    expect(vaultApi.resolveBrowserSave).toHaveBeenCalledWith('approval-1', false, 'login-a')
  })
})

describe('never for this site', () => {
  it('sends only the approval id and shows the returned list', async () => {
    vaultApi.neverSaveBrowserSite.mockResolvedValue(['https://example.test'])
    const { stores, feedback, controller } = harness('login-a')
    controller.receive(request('new'))

    await controller.neverForSite()

    expect(vaultApi.neverSaveBrowserSite).toHaveBeenCalledWith('approval-1')
    expect(vaultApi.resolveBrowserSave).not.toHaveBeenCalled()
    expect(get(neverSaveSites)).toEqual(['https://example.test'])
    expect(stores.browserSave.value().request).toBeNull()
    expect(feedback.state.value().notice?.title).toBe('Site skipped')
  })

  it('reports a refusal and still closes the prompt', async () => {
    vaultApi.neverSaveBrowserSite.mockRejectedValue(new Error('That browser approval expired or is no longer available.'))
    const { stores, feedback, controller } = harness('login-a')
    controller.receive(request('new'))

    await controller.neverForSite()

    expect(stores.browserSave.value().request).toBeNull()
    expect(stores.browserSave.value().working).toBe(false)
    expect(feedback.state.value().errorMessage).toBeTruthy()
  })

  it('forgets the list when the vault locks', () => {
    neverSaveSites.set(['https://example.test'])
    const { controller } = harness('login-a')

    controller.clearSecrets()

    expect(get(neverSaveSites)).toBeNull()
  })
})

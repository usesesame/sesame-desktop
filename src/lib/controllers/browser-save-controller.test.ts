import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { BrowserSaveRequest, VaultSnapshot } from '../types'
import { createAppStores } from '../stores/app-stores'
import { createBrowserSaveController } from './browser-save-controller'
import { createFeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  getPendingBrowserSave: vi.fn(),
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

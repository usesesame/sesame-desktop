import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { LoginCard, VaultSnapshot } from '../types'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createLoginController } from './login-controller'
import type { ModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  autoType: vi.fn(),
  bulkAssignFolder: vi.fn(),
  checkPasswordBreach: vi.fn(),
  copyToClipboard: vi.fn(),
  createFolder: vi.fn(),
  deleteFolder: vi.fn(),
  getLoginCard: vi.fn(),
  grantPresence: vi.fn(),
  openWebsite: vi.fn(),
  recordDiagnostic: vi.fn(),
  recordItemUse: vi.fn(),
  refreshTotp: vi.fn(),
  renameFolder: vi.fn(),
  revealLoginSecret: vi.fn(),
  saveLogin: vi.fn(),
  setItemFavourite: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  PRESENCE_REQUIRED: 'presenceRequired',
  ...vaultApi,
}))

const secrets: Record<string, string> = {
  'login-a': 'fictional-alpha-secret',
  'login-b': 'fictional-bravo-secret',
}

function card(id: string): LoginCard {
  return { id, title: `Fictional ${id}`, username: `${id}@example.test`, email: '', hasPassword: true } as unknown as LoginCard
}

function harness(activeItemId = 'login-a') {
  const stores = createAppStores()
  stores.vault.patch({
    status: { ...stores.vault.value().status, exists: true, unlocked: true },
    snapshot: { entries: [], folders: [] } as unknown as VaultSnapshot,
    loginCard: card(activeItemId),
  })
  stores.selection.patch({ activeItemId, activeItemKind: 'login' })
  const feedback = createFeedbackController()
  const modal = { open: vi.fn(), closeAll: vi.fn() } as unknown as ModalController
  const controller = createLoginController({
    stores,
    feedback,
    modal,
    refreshDiagnostics: async () => {},
    requestDelete: vi.fn(),
    requestBulkDelete: vi.fn(),
  })
  return { stores, feedback, controller }
}

function requirePresenceOnce(id: string) {
  let granted = false
  vaultApi.grantPresence.mockImplementation(async () => { granted = true })
  vaultApi.revealLoginSecret.mockImplementation(async (requested: string) => {
    if (requested === id && !granted) throw new Error('presenceRequired')
    return secrets[requested]
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vaultApi.revealLoginSecret.mockImplementation(async (id: string) => secrets[id])
  vaultApi.getLoginCard.mockImplementation(async (id: string) => card(id))
  vaultApi.recordItemUse.mockResolvedValue({ entries: [], folders: [] })
  vaultApi.copyToClipboard.mockResolvedValue(undefined)
})

describe('copying a login password', () => {
  it('copies without revealing or caching the password', async () => {
    const { controller } = harness()

    await controller.copySelectedField('password')

    expect(vaultApi.copyToClipboard).toHaveBeenCalledWith('fictional-alpha-secret')
    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '', revealedFor: '' })
  })

  it('copies after the master password check and keeps the password hidden', async () => {
    requirePresenceOnce('login-a')
    const { controller } = harness()

    await controller.copySelectedField('password')
    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: true, passwordPresenceIntent: 'copy', passwordPresenceFor: 'login-a' })

    controller.state.patch({ passwordPresenceSecret: 'fictional master password' })
    await controller.confirmPasswordPresence()

    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(vaultApi.copyToClipboard).toHaveBeenCalledWith('fictional-alpha-secret')
    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: false, passwordVisible: false, revealedPassword: '' })
  })

  it('still reveals after the master password check when the user asked to show it', async () => {
    requirePresenceOnce('login-a')
    const { controller } = harness()

    await controller.togglePasswordReveal()
    expect(controller.state.value().passwordPresenceIntent).toBe('reveal')
    controller.state.patch({ passwordPresenceSecret: 'fictional master password' })
    await controller.confirmPasswordPresence()

    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
    expect(controller.state.value()).toMatchObject({ passwordVisible: true, revealedPassword: 'fictional-alpha-secret', revealedFor: 'login-a' })
  })

  it('copies the password of a login that is not selected from the context menu', async () => {
    const { controller } = harness('login-a')

    await controller.copyContextField('login-b', 'password')

    expect(vaultApi.copyToClipboard).toHaveBeenCalledWith('fictional-bravo-secret')
    expect(vaultApi.recordItemUse).toHaveBeenCalledWith('login-b')
  })

  it('never copies the revealed password of another login after a cancelled check', async () => {
    const { controller } = harness('login-a')
    await controller.togglePasswordReveal()
    expect(controller.state.value().revealedPassword).toBe('fictional-alpha-secret')

    requirePresenceOnce('login-b')
    await controller.copyContextField('login-b', 'password')
    controller.cancelPasswordPresence()
    vaultApi.revealLoginSecret.mockImplementation(async (id: string) => secrets[id])
    await controller.copyContextField('login-b', 'password')

    expect(vaultApi.copyToClipboard).toHaveBeenCalledTimes(1)
    expect(vaultApi.copyToClipboard).toHaveBeenCalledWith('fictional-bravo-secret')
  })

  it('keeps the check open when the master password is wrong', async () => {
    requirePresenceOnce('login-a')
    vaultApi.grantPresence.mockRejectedValue(new Error('That master password did not match.'))
    const { controller } = harness()

    await controller.copySelectedField('password')
    controller.state.patch({ passwordPresenceSecret: 'wrong fictional password' })
    await controller.confirmPasswordPresence()

    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: true, passwordPresenceError: 'That master password did not match.', passwordVisible: false })
  })

  it('drops a pending copy when the vault locks', async () => {
    requirePresenceOnce('login-a')
    const { controller } = harness()

    await controller.copySelectedField('password')
    controller.clearSecrets()
    controller.state.patch({ passwordPresenceSecret: 'fictional master password' })
    await controller.confirmPasswordPresence()

    expect(vaultApi.grantPresence).not.toHaveBeenCalled()
    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
  })
})

/* @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { LoginCard, VaultSnapshot } from '../types'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createLoginController } from './login-controller'
import { createModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  addItemsTag: vi.fn(),
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

const STATUS = { exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 1 }

const secrets: Record<string, string> = {
  'login-a': 'fictional-alpha-secret',
  'login-b': 'fictional-bravo-secret',
}

function card(id: string): LoginCard {
  return { id, title: `Fictional ${id}`, username: `${id}@example.test`, email: '', hasPassword: true } as unknown as LoginCard
}

function snapshotWith(entries: Array<{ id: string; title: string; tags?: string[] }>): VaultSnapshot {
  return {
    vaultName: 'Fictional vault',
    revision: 1,
    folders: [],
    entries: entries.map((entry, index) => ({
      id: entry.id,
      title: entry.title,
      site: '',
      initials: 'F',
      folder: '',
      favourite: false,
      updatedAt: index,
      tags: entry.tags ?? [],
      issueKinds: [],
    })),
    items: [],
    trash: [],
    history: [],
    security: { good: 0, needsAttention: 0 },
  } as unknown as VaultSnapshot
}

function harness(activeItemId = 'login-a') {
  const stores = createAppStores()
  stores.vault.patch({
    status: STATUS,
    snapshot: snapshotWith([
      { id: 'login-a', title: 'Northwind' },
      { id: 'login-b', title: 'Contoso' },
    ]),
    loginCard: card(activeItemId),
  })
  stores.selection.patch({ activeItemId, activeItemKind: 'login' })
  const feedback = createFeedbackController()
  const deleted: string[][] = []
  const controller = createLoginController({
    stores,
    feedback,
    modal: createModalController({ stores, feedback }),
    refreshDiagnostics: async () => {},
    requestDelete: () => {},
    requestBulkDelete: (entries) => deleted.push(entries.map((entry) => entry.id)),
  })
  return { stores, feedback, controller, deleted }
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

afterEach(() => {
  vi.useRealTimers()
})

describe('copying a login password', () => {
  it('copies without revealing or caching the password', async () => {
    const { controller } = harness()

    await controller.copySelectedField('password')

    expect(vaultApi.copyToClipboard).toHaveBeenCalledWith('fictional-alpha-secret')
    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '' })
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
    expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(2)
    expect(controller.state.value()).toMatchObject({ passwordVisible: true, revealedPassword: 'fictional-alpha-secret' })
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

describe('revealing a login password', () => {
  it('asks the vault for the secret again when the same password is shown a second time', async () => {
    let reveals = 0
    vaultApi.revealLoginSecret.mockImplementation(async () => {
      reveals += 1
      return reveals === 1 ? 'fictional-alpha-secret' : 'fictional-alpha-rotated'
    })
    const { controller } = harness()

    await controller.togglePasswordReveal()
    expect(controller.state.value()).toMatchObject({ passwordVisible: true, revealedPassword: 'fictional-alpha-secret' })

    await controller.togglePasswordReveal()
    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '' })

    await controller.togglePasswordReveal()

    expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(2)
    expect(vaultApi.revealLoginSecret).toHaveBeenLastCalledWith('login-a')
    expect(controller.state.value()).toMatchObject({ passwordVisible: true, revealedPassword: 'fictional-alpha-rotated' })
  })

  it('clears the shown password when the reveal times out', async () => {
    vi.useFakeTimers()
    const { controller } = harness()

    await controller.togglePasswordReveal()
    expect(controller.state.value()).toMatchObject({ passwordVisible: true, revealedPassword: 'fictional-alpha-secret' })

    vi.advanceTimersByTime(30_000)

    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '' })
  })

  it('asks for the master password again when the presence window has closed', async () => {
    let presenceOpen = true
    vaultApi.revealLoginSecret.mockImplementation(async () => {
      if (!presenceOpen) throw new Error('presenceRequired')
      return 'fictional-alpha-secret'
    })
    const { controller } = harness()

    await controller.togglePasswordReveal()
    await controller.togglePasswordReveal()
    presenceOpen = false

    await controller.togglePasswordReveal()

    expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(2)
    expect(controller.state.value()).toMatchObject({
      passwordVisible: false,
      passwordPresenceRequired: true,
      passwordPresenceFor: 'login-a',
      passwordPresenceIntent: 'reveal',
    })
  })

  it('drops the shown password when another login is selected', async () => {
    const { controller } = harness('login-a')
    await controller.togglePasswordReveal()
    expect(controller.state.value().revealedPassword).toBe('fictional-alpha-secret')

    await controller.selectEntry('login-b')

    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '' })
  })

  it('drops the shown password when the vault locks', async () => {
    const { controller } = harness()
    await controller.togglePasswordReveal()
    expect(controller.state.value().revealedPassword).toBe('fictional-alpha-secret')

    controller.clearSecrets()

    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '', passwordPresenceRequired: false })
  })
})

describe('bulk item actions', () => {
  it('adds the entered tag to every selected item', async () => {
    const { stores, feedback, controller } = harness()
    const updated = snapshotWith([
      { id: 'login-a', title: 'Northwind', tags: ['Travel'] },
      { id: 'login-b', title: 'Contoso', tags: ['Travel'] },
    ])
    vaultApi.addItemsTag.mockResolvedValue(updated)
    controller.startMultiSelect('login-a')
    controller.toggleMultiSelect('login-b', true)
    controller.setBulkTag('Travel')

    await controller.bulkTagSelected()

    expect(vaultApi.addItemsTag).toHaveBeenCalledWith(['login-a', 'login-b'], 'Travel')
    expect(stores.vault.value().snapshot).toBe(updated)
    expect(feedback.state.value().notice?.title).toBe('Tag added')
    expect(controller.state.value().multiSelect).toBe(false)
    expect(controller.state.value().bulkTag).toBe('')
  })

  it('refuses an empty tag before calling the backend', async () => {
    const { feedback, controller } = harness()
    controller.startMultiSelect('login-a')
    controller.setBulkTag('   ')

    await controller.bulkTagSelected()

    expect(vaultApi.addItemsTag).not.toHaveBeenCalled()
    expect(feedback.state.value().errorMessage).toBe('Enter a tag to add.')
  })

  it('moves the selected items through the existing folder command', async () => {
    const { stores, controller } = harness()
    const updated = snapshotWith([{ id: 'login-a', title: 'Northwind' }])
    vaultApi.bulkAssignFolder.mockResolvedValue(updated)
    controller.startMultiSelect('login-a')
    controller.setBulkFolderId('folder-1')

    await controller.bulkMoveSelected()

    expect(vaultApi.bulkAssignFolder).toHaveBeenCalledWith(['login-a'], 'folder-1')
    expect(stores.vault.value().snapshot).toBe(updated)
    expect(controller.state.value().multiSelect).toBe(false)
  })

  it('favourites every selected item', async () => {
    const { controller } = harness()
    const updated = snapshotWith([
      { id: 'login-a', title: 'Northwind' },
      { id: 'login-b', title: 'Contoso' },
    ])
    vaultApi.setItemFavourite.mockResolvedValue(updated)
    controller.startMultiSelect('login-a')
    controller.toggleMultiSelect('login-b', true)

    await controller.bulkFavouriteSelected()

    expect(vaultApi.setItemFavourite).toHaveBeenCalledTimes(2)
    expect(vaultApi.setItemFavourite).toHaveBeenCalledWith('login-a', true)
    expect(vaultApi.setItemFavourite).toHaveBeenCalledWith('login-b', true)
    expect(controller.state.value().multiSelect).toBe(false)
  })

  it('routes bulk delete through the approval path', () => {
    const { controller, deleted } = harness()
    controller.startMultiSelect('login-a')
    controller.toggleMultiSelect('login-b', true)

    controller.bulkDeleteSelected()

    expect(deleted).toEqual([['login-a', 'login-b']])
    expect(vaultApi.addItemsTag).not.toHaveBeenCalled()
  })
})

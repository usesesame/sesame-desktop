/* @vitest-environment jsdom */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import type { VaultSnapshot } from '../types'
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
  renameFolder: vi.fn(),
  recordItemUse: vi.fn(),
  revealLoginSecret: vi.fn(),
  saveLogin: vi.fn(),
  setItemFavourite: vi.fn(),
}))

vi.mock('../vault', () => ({
  PRESENCE_REQUIRED: 'presenceRequired',
  refreshTotp: vi.fn(),
  ...vaultApi,
}))

const STATUS = { exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 1 }

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

function harness() {
  const stores = createAppStores()
  stores.vault.patch({
    status: STATUS,
    snapshot: snapshotWith([
      { id: 'login-a', title: 'Northwind' },
      { id: 'login-b', title: 'Contoso' },
    ]),
  })
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

beforeEach(() => {
  vi.clearAllMocks()
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

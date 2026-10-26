/* @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { LoginCard, VaultSnapshot } from '../types'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createLoginController } from './login-controller'
import { createModalController } from './modal-controller'
import { createPresenceController } from './presence-controller'

const vaultApi = vi.hoisted(() => ({
  addItemsTag: vi.fn(),
  autoType: vi.fn(),
  bulkAssignFolder: vi.fn(),
  checkLoginBreach: vi.fn(),
  checkReleasePresence: vi.fn(),
  copyItemField: vi.fn(),
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
  const presence = createPresenceController()
  const controller = createLoginController({
    stores,
    feedback,
    modal: createModalController({ stores, feedback }),
    presence,
    refreshDiagnostics: async () => {},
    requestDelete: () => {},
    requestBulkDelete: (entries) => deleted.push(entries.map((entry) => entry.id)),
  })
  return { stores, feedback, controller, deleted, presence }
}

function requirePresenceOnce(id: string) {
  let granted = false
  vaultApi.grantPresence.mockImplementation(async () => { granted = true })
  vaultApi.revealLoginSecret.mockImplementation(async (requested: string) => {
    if (requested === id && !granted) throw new Error('presenceRequired')
    return secrets[requested]
  })
  vaultApi.copyItemField.mockImplementation(async (_kind: string, requested: string) => {
    if (requested === id && !granted) throw new Error('presenceRequired')
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vaultApi.revealLoginSecret.mockImplementation(async (id: string) => secrets[id])
  vaultApi.getLoginCard.mockImplementation(async (id: string) => card(id))
  vaultApi.recordItemUse.mockResolvedValue({ entries: [], folders: [] })
  vaultApi.copyToClipboard.mockResolvedValue(undefined)
  vaultApi.copyItemField.mockResolvedValue(undefined)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('copying a login password', () => {
  it('copies without revealing or caching the password', async () => {
    const { controller } = harness()

    await controller.copySelectedField('password')

    expect(vaultApi.copyItemField).toHaveBeenCalledWith('login', 'login-a', 'password')
    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
    expect(vaultApi.revealLoginSecret).not.toHaveBeenCalled()
    expect(controller.state.value()).toMatchObject({ passwordVisible: false, revealedPassword: '' })
  })

  it('copies after the master password check and keeps the password hidden', async () => {
    requirePresenceOnce('login-a')
    const { controller } = harness()

    await controller.copySelectedField('password')
    expect(vaultApi.copyItemField).toHaveBeenCalledTimes(1)
    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: true, passwordPresenceIntent: 'copy', passwordPresenceFor: 'login-a' })

    controller.state.patch({ passwordPresenceSecret: 'fictional master password' })
    await controller.confirmPasswordPresence()

    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(vaultApi.copyItemField).toHaveBeenCalledTimes(2)
    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
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

    expect(vaultApi.copyItemField).toHaveBeenCalledWith('login', 'login-b', 'password')
    expect(vaultApi.recordItemUse).toHaveBeenCalledWith('login-b')
  })

  it('never copies the revealed password of another login after a cancelled check', async () => {
    const { controller } = harness('login-a')
    await controller.togglePasswordReveal()
    expect(controller.state.value().revealedPassword).toBe('fictional-alpha-secret')

    requirePresenceOnce('login-b')
    await controller.copyContextField('login-b', 'password')
    controller.cancelPasswordPresence()
    vaultApi.copyItemField.mockResolvedValue(undefined)
    await controller.copyContextField('login-b', 'password')

    expect(vaultApi.copyItemField).toHaveBeenLastCalledWith('login', 'login-b', 'password')
    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
  })

  it('keeps the check open when the master password is wrong', async () => {
    requirePresenceOnce('login-a')
    vaultApi.grantPresence.mockRejectedValue(new Error('That master password did not match.'))
    const { controller } = harness()

    await controller.copySelectedField('password')
    controller.state.patch({ passwordPresenceSecret: 'wrong fictional password' })
    await controller.confirmPasswordPresence()

    expect(vaultApi.copyItemField).toHaveBeenCalledTimes(1)
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
    expect(vaultApi.copyItemField).toHaveBeenCalledTimes(1)
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

describe('auto-type', () => {
  it('asks for the master password before the countdown and types after it', async () => {
    vi.useFakeTimers()
    vaultApi.checkReleasePresence.mockRejectedValueOnce(new Error('presenceRequired'))
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.autoType.mockResolvedValue(undefined)
    const { controller } = harness()

    await controller.startAutoType()

    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: true, passwordPresenceIntent: 'autotype', autoTypeCountdown: 0 })
    await vi.advanceTimersByTimeAsync(5_000)
    expect(vaultApi.autoType).not.toHaveBeenCalled()

    controller.state.patch({ passwordPresenceSecret: 'fictional master password' })
    await controller.confirmPasswordPresence()
    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: false, autoTypeCountdown: 3 })
    expect(vaultApi.autoType).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(3_000)
    expect(vaultApi.autoType).toHaveBeenCalledWith('login-a')
  })

  it('starts the countdown at once while presence is still granted', async () => {
    vi.useFakeTimers()
    vaultApi.checkReleasePresence.mockResolvedValue(undefined)
    const { controller } = harness()

    await controller.startAutoType()

    expect(controller.state.value()).toMatchObject({ passwordPresenceRequired: false, autoTypeCountdown: 3 })
    controller.cancelAutoType()
  })

  it('never types after a cancelled master password check', async () => {
    vi.useFakeTimers()
    vaultApi.checkReleasePresence.mockRejectedValueOnce(new Error('presenceRequired'))
    const { controller } = harness()

    await controller.startAutoType()
    controller.cancelPasswordPresence()
    await vi.advanceTimersByTimeAsync(10_000)

    expect(vaultApi.autoType).not.toHaveBeenCalled()
  })
})

describe('secrets other than the password', () => {
  it('copies the backup codes in the host and passes nothing through the window', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ loginCard: { ...card('login-a'), backupCodeCount: 3 } })

    controller.copyBackupCodes()
    await vi.waitFor(() => expect(vaultApi.copyItemField).toHaveBeenCalledWith('login', 'login-a', 'backupCodes'))

    expect(vaultApi.copyToClipboard).not.toHaveBeenCalled()
  })

  it('does nothing for backup codes a login does not hold', () => {
    const { controller } = harness()

    controller.copyBackupCodes()

    expect(vaultApi.copyItemField).not.toHaveBeenCalled()
  })

  it('asks for the master password before copying backup codes and copies after the grant', async () => {
    const { controller, stores, presence } = harness()
    stores.vault.patch({ loginCard: { ...card('login-a'), backupCodeCount: 3 } })
    let granted = false
    vaultApi.grantPresence.mockImplementation(async () => { granted = true })
    vaultApi.copyItemField.mockImplementation(async () => {
      if (!granted) throw new Error('presenceRequired')
    })

    controller.copyBackupCodes()
    await vi.waitFor(() => expect(presence.state.value().open).toBe(true))
    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()

    expect(vaultApi.copyItemField).toHaveBeenCalledTimes(2)
  })

  it('copies a secret legacy value by its position', async () => {
    const { controller } = harness()

    controller.copyLegacySecret(1, 'Old PIN')
    await vi.waitFor(() => expect(vaultApi.copyItemField).toHaveBeenCalledWith('login', 'login-a', 'legacy:1'))
  })

  it('checks the password for breaches in the host without revealing it', async () => {
    const { controller } = harness()
    vaultApi.checkLoginBreach.mockResolvedValue({ breached: true, count: 4 })
    controller.toggleBreachCheck()

    await controller.runBreachCheck()

    expect(vaultApi.checkLoginBreach).toHaveBeenCalledWith('login-a')
    expect(vaultApi.revealLoginSecret).not.toHaveBeenCalled()
    expect(controller.state.value()).toMatchObject({ breachCheckResult: { breached: true, count: 4 }, revealedPassword: '' })
  })

  it('asks for the master password before a breach check and runs it after the grant', async () => {
    const { controller, presence } = harness()
    let granted = false
    vaultApi.grantPresence.mockImplementation(async () => { granted = true })
    vaultApi.checkLoginBreach.mockImplementation(async () => {
      if (!granted) throw new Error('presenceRequired')
      return { breached: false, count: 0 }
    })
    controller.toggleBreachCheck()

    await controller.runBreachCheck()
    expect(presence.state.value()).toMatchObject({ open: true, intent: 'check-password' })
    expect(controller.state.value().breachCheckWorking).toBe(false)

    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()

    expect(controller.state.value().breachCheckResult).toEqual({ breached: false, count: 0 })
  })

  it('opens the editor without backup codes and keeps the saved ones unless told otherwise', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ loginCard: { ...card('login-a'), backupCodeCount: 2 } })

    controller.openEditor()

    expect(controller.state.value().loginDraft).toMatchObject({ backupCodes: [], keepBackupCodes: true })
    expect(controller.state.value().editorBackupCodeCount).toBe(2)
  })

  it('sends the keep flag with a save so the host retains the codes', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ loginCard: { ...card('login-a'), backupCodeCount: 2 } })
    vaultApi.saveLogin.mockResolvedValue({ id: 'login-a', snapshot: { entries: [], folders: [] } })

    controller.openEditor()
    await controller.submit(false)

    expect(vaultApi.saveLogin).toHaveBeenCalledWith(expect.objectContaining({ backupCodes: [], keepBackupCodes: true }))
  })
  it('keeps the search and filters after editing a login that stays in its folder', async () => {
    const { controller, stores } = harness()
    stores.selection.patch({ collectionFilter: 'folder-1', securityFilter: 'weak', searchQuery: 'north' })
    const before = snapshotWith([{ id: 'login-a', title: 'Northwind' }])
    before.entries[0].folderId = 'folder-1'
    stores.vault.patch({ snapshot: before })
    const after = snapshotWith([{ id: 'login-a', title: 'Northwind' }])
    after.entries[0].folderId = 'folder-1'
    vaultApi.saveLogin.mockResolvedValue({ id: 'login-a', snapshot: after })
    vaultApi.getLoginCard.mockResolvedValue(card('login-a'))

    controller.openEditor()
    await controller.submit(false)

    expect(stores.selection.value()).toMatchObject({ collectionFilter: 'folder-1', securityFilter: 'weak', searchQuery: 'north' })
  })

  it('follows a login to its new folder when an edit moves it', async () => {
    const { controller, stores } = harness()
    stores.selection.patch({ collectionFilter: 'folder-1', securityFilter: 'weak', searchQuery: 'north' })
    const before = snapshotWith([{ id: 'login-a', title: 'Northwind' }])
    before.entries[0].folderId = 'folder-1'
    stores.vault.patch({ snapshot: before })
    const after = snapshotWith([{ id: 'login-a', title: 'Northwind' }])
    after.entries[0].folderId = 'folder-2'
    vaultApi.saveLogin.mockResolvedValue({ id: 'login-a', snapshot: after })
    vaultApi.getLoginCard.mockResolvedValue(card('login-a'))

    controller.openEditor()
    await controller.submit(false)

    expect(stores.selection.value()).toMatchObject({ collectionFilter: 'folder-2', securityFilter: null, searchQuery: '' })
  })

  it('shows a new login by clearing the search and opening its folder', async () => {
    const { controller, stores } = harness()
    stores.selection.patch({ collectionFilter: 'folder-1', securityFilter: 'weak', searchQuery: 'north' })
    const after = snapshotWith([{ id: 'login-a', title: 'Northwind' }, { id: 'login-new', title: 'Fresh' }])
    after.entries[1].folderId = 'folder-2'
    vaultApi.saveLogin.mockResolvedValue({ id: 'login-new', snapshot: after })
    vaultApi.getLoginCard.mockResolvedValue(card('login-new'))

    controller.openNew()
    await controller.submit(false)

    expect(stores.selection.value()).toMatchObject({ collectionFilter: 'folder-2', securityFilter: null, searchQuery: '' })
  })
})

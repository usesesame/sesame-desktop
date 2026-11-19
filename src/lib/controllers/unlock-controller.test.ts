/* @vitest-environment jsdom */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { VaultSnapshot } from '../types'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'
import { createOnboardingController } from './onboarding-controller'
import { createUnlockController } from './unlock-controller'

const vaultApi = vi.hoisted(() => ({
  completeRecoverySetup: vi.fn(),
  createVault: vi.fn(),
  getVaultStatus: vi.fn(),
  lockVault: vi.fn(),
  resumeRecoverySetup: vi.fn(),
  unlockVault: vi.fn(),
  unlockWithPin: vi.fn(),
  unlockWithRecovery: vi.fn(),
  unlockWithWindowsHello: vi.fn(),
}))

vi.mock('../vault', () => vaultApi)

function snapshotOf(ids: string[], updatedAt = 1): VaultSnapshot {
  const entries = ids.map((id) => ({ id, title: id, site: `${id}.example`, initials: 'X', folder: '', favourite: false, updatedAt, tags: [], issueKinds: [] }))
  return { vaultName: 'Fictional vault', revision: 1, folders: [], entries, items: [], trash: [], history: [] } as unknown as VaultSnapshot
}

function harness(options: { unlocked?: boolean; selected?: string | null; shown?: string[] } = {}) {
  const stores = createAppStores()
  stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: options.unlocked ?? true }, snapshot: snapshotOf(options.shown ?? (options.selected ? [options.selected] : [])) })
  stores.selection.patch({ activeItemId: options.selected ?? null, activeItemKind: options.selected ? 'login' : null })
  const feedback = createFeedbackController()
  const modal = createModalController({ stores, feedback })
  const selectItem = vi.fn(async (id: string) => {
    stores.selection.patch({ activeItemId: id, activeItemKind: 'login' })
  })
  const clearSelection = vi.fn(() => stores.selection.patch({ activeItemId: null, activeItemKind: null }))
  const refreshActiveView = vi.fn(async () => {})
  const controller = createUnlockController({
    stores,
    feedback,
    selectItem,
    clearSelection,
    clearSessionState: vi.fn(),
    rejectBrowserFill: vi.fn(async () => {}),
    refreshActiveView,
    openPinSetup: vi.fn(),
    onboarding: createOnboardingController({ stores, onOpenPinSetup: vi.fn(), onRecoveryVerified: vi.fn() }),
    modal,
  })
  return { controller, stores, feedback, modal, selectItem, clearSelection, refreshActiveView }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('showing what a sync applied', () => {
  it('lists the logins another device added without a lock and unlock, and says nothing about it', async () => {
    const { controller, stores, feedback, selectItem } = harness()
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first', 'second']))
    await controller.reloadAfterSync()
    expect(vaultApi.unlockVault).toHaveBeenCalledWith({ masterPassword: '' }, true)
    expect(stores.vault.value().snapshot?.entries.map((entry) => entry.id)).toEqual(['first', 'second'])
    expect(selectItem).toHaveBeenCalledWith('first', 'login')
    expect(feedback.state.value().notice).toBeNull()
  })

  it('leaves the login the person is looking at alone when it did not change', async () => {
    const { controller, stores, selectItem, refreshActiveView } = harness({ selected: 'second' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first', 'second']))
    await controller.reloadAfterSync()
    expect(selectItem).not.toHaveBeenCalled()
    expect(stores.selection.value().activeItemId).toBe('second')
    expect(refreshActiveView).toHaveBeenCalledTimes(1)
  })

  it('reloads the details of the login on screen when another device changed it', async () => {
    const { controller, selectItem } = harness({ selected: 'second' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first', 'second'], 2))
    await controller.reloadAfterSync()
    expect(selectItem).toHaveBeenCalledTimes(1)
    expect(selectItem).toHaveBeenCalledWith('second', 'login')
  })

  it('shows the new list but leaves the selection alone while a dialog is open', async () => {
    const { controller, stores, modal, selectItem, clearSelection } = harness({ selected: 'second' })
    modal.open({ kind: 'login-editor' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first']))
    await controller.reloadAfterSync()
    expect(stores.vault.value().snapshot?.entries.map((entry) => entry.id)).toEqual(['first'])
    expect(stores.selection.value().activeItemId).toBe('second')
    expect(selectItem).not.toHaveBeenCalled()
    expect(clearSelection).not.toHaveBeenCalled()
  })

  it('moves to the first login when the one on screen was removed on another device', async () => {
    const { controller, selectItem } = harness({ selected: 'gone' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first']))
    await controller.reloadAfterSync()
    expect(selectItem).toHaveBeenCalledWith('first', 'login')
  })

  it('clears the selection when the vault became empty', async () => {
    const { controller, clearSelection } = harness({ selected: 'gone' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf([]))
    await controller.reloadAfterSync()
    expect(clearSelection).toHaveBeenCalledTimes(1)
  })

  it('reads nothing while the vault is locked', async () => {
    const { controller, stores } = harness({ unlocked: false })
    await controller.reloadAfterSync()
    expect(vaultApi.unlockVault).not.toHaveBeenCalled()
    expect(stores.vault.value().snapshot?.entries).toEqual([])
  })

  it('drops the answer when the vault was locked while it was being read', async () => {
    const { controller, stores } = harness()
    vaultApi.unlockVault.mockImplementation(async () => {
      stores.vault.patch({ snapshot: null, status: { ...stores.vault.value().status, unlocked: false } })
      return snapshotOf(['first'])
    })
    await controller.reloadAfterSync()
    expect(stores.vault.value().snapshot).toBeNull()
  })

  it('does not raise an error for a read that failed because the vault was locked meanwhile', async () => {
    const { controller, stores, feedback } = harness()
    vaultApi.unlockVault.mockImplementation(async () => {
      stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: false } })
      throw 'Unlock Sesame first.'
    })
    await controller.reloadAfterSync()
    expect(feedback.state.value().errorMessage).toBe('')
  })

  it('shows the error when the read fails on an unlocked vault', async () => {
    const { controller, feedback } = harness()
    vaultApi.unlockVault.mockRejectedValue('Sesame could not read the vault.')
    await controller.reloadAfterSync()
    expect(feedback.state.value().errorMessage).not.toBe('')
  })

  it('runs one read when two syncs apply changes at once and a second one after it', async () => {
    const { controller } = harness()
    let release: (snapshot: VaultSnapshot) => void = () => {}
    vaultApi.unlockVault.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['later']))
    const first = controller.reloadAfterSync()
    const second = controller.reloadAfterSync()
    release(snapshotOf(['earlier']))
    await Promise.all([first, second])
    expect(vaultApi.unlockVault).toHaveBeenCalledTimes(2)
  })
})

describe('locking the vault', () => {
  it('clears the search, the filters and the view so the next unlock starts clean', () => {
    const { controller, stores } = harness({ selected: 'login-a' })
    stores.selection.patch({ searchQuery: 'north', securityFilter: 'reused-password', collectionFilter: 'folder-1', activeView: 'security' })

    controller.applyLockedUi('Vault locked.')

    expect(stores.selection.value()).toMatchObject({ searchQuery: '', securityFilter: null, collectionFilter: null, activeView: 'vault' })
  })
})

describe('unlocking with the master password', () => {
  it('shows the busy state while the key is derived and ignores a second press meanwhile', async () => {
    const { controller, stores } = harness({ unlocked: false })
    stores.vault.patch({ status: { ...stores.vault.value().status, exists: true, unlocked: false } })
    controller.state.patch({ isWorking: false, masterPassword: 'fictional master password' })
    let finish: (snapshot: VaultSnapshot) => void = () => {}
    vaultApi.unlockVault.mockReturnValue(new Promise<VaultSnapshot>((resolve) => { finish = resolve }))

    const first = controller.submitMasterPassword()
    expect(controller.state.value().isWorking).toBe(true)
    await controller.submitMasterPassword()
    await vi.waitFor(() => expect(vaultApi.unlockVault).toHaveBeenCalledTimes(1))
    expect(controller.state.value().isWorking).toBe(true)

    finish(snapshotOf(['first']))
    await first
    expect(vaultApi.unlockVault).toHaveBeenCalledTimes(1)
    expect(controller.state.value().isWorking).toBe(false)
  })
})

describe('an unlock answer that arrives after the vault locked again', () => {
  const lockedStatus = { exists: true, unlocked: false, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 0 }

  function lockedHarness() {
    const result = harness({ unlocked: false })
    result.stores.vault.patch({ snapshot: null, status: { ...result.stores.vault.value().status, exists: true, unlocked: false } })
    result.controller.state.patch({ isWorking: false })
    return result
  }

  it('keeps no snapshot and says nothing about an unlock with the master password', async () => {
    const { controller, stores, feedback } = lockedHarness()
    controller.state.patch({ masterPassword: 'fictional master password' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first']))
    vaultApi.getVaultStatus.mockResolvedValue(lockedStatus)

    await controller.submitMasterPassword()

    expect(stores.vault.value().snapshot).toBeNull()
    expect(stores.vault.value().status.unlocked).toBe(false)
    expect(feedback.state.value().notice).toBeNull()
  })

  it('keeps no snapshot from a PIN unlock', async () => {
    const { controller, stores } = lockedHarness()
    controller.state.patch({ unlockPin: '135790' })
    vaultApi.unlockWithPin.mockResolvedValue(snapshotOf(['first']))
    vaultApi.getVaultStatus.mockResolvedValue(lockedStatus)

    await controller.unlockUsingPin()

    expect(stores.vault.value().snapshot).toBeNull()
  })

  it('keeps no snapshot or recovery kit when the vault locked while setup resumed', async () => {
    const { controller, stores } = lockedHarness()
    controller.state.patch({ masterPassword: 'fictional master password' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf([]))
    vaultApi.resumeRecoverySetup.mockResolvedValue('FICTIONAL-KIT')
    vaultApi.getVaultStatus.mockResolvedValueOnce({ ...lockedStatus, unlocked: true, onboardingRequired: true })
    vaultApi.getVaultStatus.mockResolvedValue({ ...lockedStatus, onboardingRequired: true })

    await controller.submitMasterPassword()

    expect(stores.vault.value().snapshot).toBeNull()
    expect(controller.state.value().recoveryKit).toBe('')
  })

  it('keeps no snapshot or recovery kit from a new vault that locked before the answer arrived', async () => {
    const { controller, stores } = lockedHarness()
    stores.vault.patch({ status: { ...stores.vault.value().status, exists: false } })
    controller.state.patch({ masterPassword: 'fictional master password', confirmPassword: 'fictional master password' })
    vaultApi.createVault.mockResolvedValue({ snapshot: snapshotOf([]), recoveryKit: 'FICTIONAL-KIT' })
    vaultApi.getVaultStatus.mockResolvedValue({ ...lockedStatus, onboardingRequired: true })

    await controller.submitMasterPassword()

    expect(stores.vault.value().snapshot).toBeNull()
    expect(stores.vault.value().status.unlocked).toBe(false)
    expect(controller.state.value().recoveryKit).toBe('')
    expect(controller.state.value().masterPassword).toBe('')
  })

  it('installs the snapshot when the vault is still unlocked', async () => {
    const { controller, stores, feedback } = lockedHarness()
    controller.state.patch({ masterPassword: 'fictional master password' })
    vaultApi.unlockVault.mockResolvedValue(snapshotOf(['first']))
    vaultApi.getVaultStatus.mockResolvedValue({ ...lockedStatus, unlocked: true })

    await controller.submitMasterPassword()

    expect(stores.vault.value().snapshot?.entries.map((entry) => entry.id)).toEqual(['first'])
    expect(feedback.state.value().notice).not.toBeNull()
  })
})

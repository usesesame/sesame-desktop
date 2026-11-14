import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import type { VaultSnapshot } from '../types'
import { createFeedbackController } from './feedback-controller'
import { undoDeleteAction } from './undo-delete'

const vaultApi = vi.hoisted(() => ({ restoreTrashedItem: vi.fn() }))
vi.mock('../vault', () => vaultApi)

function snapshot(marker: string) {
  return { marker } as unknown as VaultSnapshot
}

function harness() {
  const stores = createAppStores()
  stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: true } })
  const feedback = createFeedbackController()
  return { stores, feedback }
}

beforeEach(() => vi.clearAllMocks())

describe('undoing a delete', () => {
  it('restores every deleted item from Trash and shows the restored vault', async () => {
    const { stores, feedback } = harness()
    vaultApi.restoreTrashedItem
      .mockResolvedValueOnce({ restoredId: 'login-a', snapshot: snapshot('first') })
      .mockResolvedValueOnce({ restoredId: 'login-b', snapshot: snapshot('second') })
    undoDeleteAction(['login-a', 'login-b'], { stores, feedback }).run()
    await vi.waitFor(() => expect(get(feedback.state).notice?.title).toBe('Items restored'))
    expect(vaultApi.restoreTrashedItem.mock.calls).toEqual([['login-a'], ['login-b']])
    expect(stores.vault.value().snapshot).toEqual(snapshot('second'))
  })

  it('says how many came back when a later restore fails', async () => {
    const { stores, feedback } = harness()
    vaultApi.restoreTrashedItem
      .mockResolvedValueOnce({ restoredId: 'login-a', snapshot: snapshot('first') })
      .mockRejectedValueOnce(new Error('Unlock your vault before restoring an item.'))
    undoDeleteAction(['login-a', 'login-b'], { stores, feedback }).run()
    await vi.waitFor(() => expect(get(feedback.state).errorMessage).toBe('Sesame restored 1 of 2 items. The rest are still in Trash.'))
    expect(stores.vault.value().snapshot).toEqual(snapshot('first'))
  })

  it('shows the vault error when nothing could be restored', async () => {
    const { stores, feedback } = harness()
    vaultApi.restoreTrashedItem.mockRejectedValueOnce(new Error('Unlock your vault before restoring an item.'))
    undoDeleteAction(['login-a'], { stores, feedback }).run()
    await vi.waitFor(() => expect(get(feedback.state).errorMessage).toBe('Unlock your vault before restoring an item.'))
  })

  it('leaves the vault view alone when the vault locked while the restore was running', async () => {
    const { stores, feedback } = harness()
    vaultApi.restoreTrashedItem.mockImplementationOnce(async () => {
      stores.vault.patch({ status: { ...stores.vault.value().status, unlocked: false }, snapshot: null })
      return { restoredId: 'login-a', snapshot: snapshot('after lock') }
    })
    undoDeleteAction(['login-a'], { stores, feedback }).run()
    await vi.waitFor(() => expect(vaultApi.restoreTrashedItem).toHaveBeenCalledOnce())
    await Promise.resolve()
    expect(stores.vault.value().snapshot).toBeNull()
    expect(get(feedback.state).notice).toBeNull()
  })
})

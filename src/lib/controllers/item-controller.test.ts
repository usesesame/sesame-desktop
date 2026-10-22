import { get } from 'svelte/store'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AppStores } from '../stores/app-stores'
import type { RecordKind } from '../item-fields'
import type { VaultSnapshot } from '../types'
import { copyItemField, grantPresence, recordItemUse, releaseItemField, searchItems, setSecureNoteLock } from '../vault'
import { createFeedbackController } from './feedback-controller'
import { createItemController, SEARCH_DEBOUNCE_MS, SECRET_REVEAL_TIMEOUT_MS, type RecordEditor } from './item-controller'
import { createPresenceController } from './presence-controller'
import type { LoginController } from './login-controller'

vi.mock('../vault', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../vault')>()
  return {
    ...actual,
    searchItems: vi.fn(),
    releaseItemField: vi.fn(),
    copyItemField: vi.fn(),
    grantPresence: vi.fn(),
    recordItemUse: vi.fn(),
    setSecureNoteLock: vi.fn(),
  }
})

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
})

const recordKinds: RecordKind[] = ['identity', 'secure_note', 'card', 'wifi_network', 'ssh_key', 'software_license', 'document', 'custom_record']

function fakeStore<T extends object>(initial: T) {
  let value = initial
  return {
    subscribe: (run: (state: T) => void) => {
      run(value)
      return () => {}
    },
    set: (next: T) => { value = next },
    patch: (values: Partial<T>) => { value = { ...value, ...values } },
    value: () => value,
  }
}

function fakeStores(): AppStores {
  return {
    selection: fakeStore({
      activeItemId: null as string | null,
      activeItemKind: null as string | null,
      searchQuery: '',
      sortMode: 'name' as const,
      securityFilter: null,
      categoryFilter: null,
      collectionFilter: null,
      recentItemIds: [] as string[],
    }),
    settings: fakeStore({ clipboardClearSeconds: 30 }),
    vault: fakeStore({ status: {}, snapshot: null, loginCard: null }),
  } as unknown as AppStores
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

function harness() {
  const calls: string[] = []
  const editors = Object.fromEntries(recordKinds.map((kind) => [kind, {
    openNew: () => { calls.push(`${kind}:new`) },
    openEditor: (id: string) => { calls.push(`${kind}:edit:${id}`) },
    requestDelete: (id: string, title: string) => { calls.push(`${kind}:delete:${id}:${title}`) },
  }])) as Record<RecordKind, RecordEditor>
  const login = { openEditor: () => { calls.push('login:edit') }, openNew: () => {}, clearSelection: () => {}, selectEntry: async () => {} } as unknown as LoginController
  const stores = fakeStores()
  const feedback = createFeedbackController()
  const presence = createPresenceController()
  const controller = createItemController({ stores, feedback, login, presence, editors })
  return { controller, calls, stores, feedback, presence }
}

describe('context menu targets', () => {
  it('opens the editor for the named item while another item is active', async () => {
    const { controller, calls } = harness()
    await controller.openEditorFor('card-1', 'card')
    expect(calls).toEqual(['card:edit:card-1'])
  })

  it('deletes the named item with its own title while another item is active', () => {
    const { controller, calls } = harness()
    controller.requestDeleteFor('card-1', 'card', 'Travel card')
    expect(calls).toEqual(['card:delete:card-1:Travel card'])
  })

  it('leaves login items to the login controller and skips a missing title', async () => {
    const { controller, calls } = harness()
    await controller.openEditorFor('login-1', 'login')
    controller.requestDeleteFor('login-1', 'login', 'Mail')
    controller.requestDeleteFor('card-1', 'card', '')
    expect(calls).toEqual(['login:edit'])
  })
})

describe('search rank order', () => {
  function visibleIds(controller: ReturnType<typeof createItemController>): string[] {
    return get(controller.visibleItems).map((item) => item.id)
  }

  async function settleDebounce() {
    await vi.advanceTimersByTimeAsync(SEARCH_DEBOUNCE_MS)
  }

  function snapshotOfThree() {
    return snapshotWith([
      { id: 'a', title: 'Alpha' },
      { id: 'b', title: 'Beta' },
      { id: 'c', title: 'Gamma' },
    ])
  }

  it('orders visible items by the ids Rust returned', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: snapshotOfThree() })
    vi.mocked(searchItems).mockResolvedValue(['c', 'a', 'b'])

    controller.runSearch('zzz')
    await settleDebounce()

    expect(visibleIds(controller)).toEqual(['c', 'a', 'b'])
  })

  it('keeps local metadata matches visible after the ranked ids', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({
      snapshot: snapshotWith([
        { id: 'a', title: 'Alpha' },
        { id: 'b', title: 'Beta', tags: ['gamma'] },
        { id: 'c', title: 'Gamma' },
      ]),
    })
    vi.mocked(searchItems).mockResolvedValue(['c'])

    controller.runSearch('gamma')
    await settleDebounce()

    expect(visibleIds(controller)).toEqual(['c', 'b'])
  })

  it('falls back to the sorted local matches when Rust search fails', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({
      snapshot: snapshotWith([
        { id: 'a', title: 'Alpha' },
        { id: 'b', title: 'Beta', tags: ['gamma'] },
        { id: 'c', title: 'Gamma' },
      ]),
    })
    vi.mocked(searchItems).mockRejectedValue(new Error('native search failed'))

    controller.runSearch('gamma')
    await settleDebounce()

    expect(visibleIds(controller)).toEqual(['b', 'c'])
  })

  it('drops a stale response that resolves after a newer search', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: snapshotOfThree() })
    let resolveStale: (ids: string[]) => void = () => {}
    vi.mocked(searchItems).mockImplementationOnce(() => new Promise((resolve) => { resolveStale = resolve }))

    controller.runSearch('zzz')
    await settleDebounce()
    vi.mocked(searchItems).mockResolvedValue(['c'])
    controller.runSearch('yyy')
    await settleDebounce()

    resolveStale(['a'])
    await vi.advanceTimersByTimeAsync(0)

    expect(visibleIds(controller)).toEqual(['c'])
  })
})

describe('search debounce', () => {
  function visibleIds(controller: ReturnType<typeof createItemController>): string[] {
    return get(controller.visibleItems).map((item) => item.id)
  }

  async function settleDebounce() {
    await vi.advanceTimersByTimeAsync(SEARCH_DEBOUNCE_MS)
  }

  it('issues one call for a burst of keystrokes, using the final query', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: snapshotWith([{ id: 'a', title: 'Alpha' }]) })
    vi.mocked(searchItems).mockResolvedValue(['a'])

    for (const query of ['n', 'no', 'nor', 'nort', 'north']) controller.runSearch(query)
    await settleDebounce()

    expect(searchItems).toHaveBeenCalledTimes(1)
    expect(searchItems).toHaveBeenCalledWith('north')
  })

  it('keeps patching the query immediately while the call waits', () => {
    const { controller, stores } = harness()

    controller.runSearch('north')

    expect(stores.selection.value().searchQuery).toBe('north')
    expect(controller.state.value().searchMatchIds).toEqual([])
    expect(searchItems).not.toHaveBeenCalled()
  })

  it('cancels a pending call when the query is cleared', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: snapshotWith([{ id: 'a', title: 'Alpha' }]) })
    vi.mocked(searchItems).mockResolvedValue(['a'])

    controller.runSearch('north')
    controller.clearSearch()
    await settleDebounce()

    expect(searchItems).not.toHaveBeenCalled()
    expect(controller.state.value().searchMatchIds).toEqual([])
    expect(visibleIds(controller)).toEqual(['a'])
  })

  it('cancels a pending call when the query becomes empty', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: snapshotWith([{ id: 'a', title: 'Alpha' }]) })

    controller.runSearch('north')
    controller.runSearch('   ')
    await settleDebounce()

    expect(searchItems).not.toHaveBeenCalled()
    expect(controller.state.value().searchMatchIds).toEqual([])
  })

  it('narrows to local matches when the debounced call fails', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({
      snapshot: snapshotWith([
        { id: 'a', title: 'Alpha' },
        { id: 'b', title: 'Beta', tags: ['gamma'] },
        { id: 'c', title: 'Gamma' },
      ]),
    })
    vi.mocked(searchItems).mockRejectedValue(new Error('native search failed'))

    controller.runSearch('gamma')
    await settleDebounce()

    expect(visibleIds(controller)).toEqual(['b', 'c'])
  })

  const FICTIONAL_VAULT_RECORDS = 5_000
  const TYPED_QUERY = 'northwind'

  function fictionalVault() {
    return snapshotWith(Array.from({ length: FICTIONAL_VAULT_RECORDS }, (_, index) => ({
      id: `fictional-login-${index}`,
      title: `Northwind account ${index}`,
    })))
  }

  function decryptedRecords() {
    return vi.mocked(searchItems).mock.calls.length * FICTIONAL_VAULT_RECORDS
  }

  it('decrypts the vault once for a typed query', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: fictionalVault() })
    vi.mocked(searchItems).mockResolvedValue([])

    for (let index = 1; index <= TYPED_QUERY.length; index += 1) controller.runSearch(TYPED_QUERY.slice(0, index))
    await settleDebounce()

    expect(searchItems).toHaveBeenCalledTimes(1)
    expect(decryptedRecords()).toBe(FICTIONAL_VAULT_RECORDS)
  })

  it('decrypts the vault once per keystroke without the debounce', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({ snapshot: fictionalVault() })
    vi.mocked(searchItems).mockResolvedValue([])

    for (let index = 1; index <= TYPED_QUERY.length; index += 1) {
      controller.runSearch(TYPED_QUERY.slice(0, index))
      await settleDebounce()
    }

    expect(searchItems).toHaveBeenCalledTimes(TYPED_QUERY.length)
    expect(decryptedRecords()).toBe(TYPED_QUERY.length * FICTIONAL_VAULT_RECORDS)
  })
})

describe('secret fields', () => {
  const presenceRequired = () => new Error('presenceRequired')

  function openCard() {
    const context = harness()
    context.stores.selection.patch({ activeItemId: 'card-1', activeItemKind: 'card' })
    context.stores.vault.patch({ status: { unlocked: true } } as never)
    return context
  }

  beforeEach(() => {
    vi.mocked(releaseItemField).mockReset()
    vi.mocked(copyItemField).mockReset()
    vi.mocked(grantPresence).mockReset()
    vi.mocked(recordItemUse).mockReset()
  })

  it('holds a revealed value only until the hide timer fires', async () => {
    const { controller } = openCard()
    vi.mocked(releaseItemField).mockResolvedValue('fictional-card-number')

    await controller.revealField('number')

    expect(releaseItemField).toHaveBeenCalledWith('card', 'card-1', 'number')
    expect(get(controller.state).revealed).toEqual({ number: 'fictional-card-number' })

    await vi.advanceTimersByTimeAsync(SECRET_REVEAL_TIMEOUT_MS)

    expect(get(controller.state).revealed).toEqual({})
  })

  it('hides a value when the person asks', async () => {
    const { controller } = openCard()
    vi.mocked(releaseItemField).mockResolvedValue('fictional-card-number')
    await controller.revealField('number')

    controller.hideField('number')

    expect(get(controller.state).revealed).toEqual({})
  })

  it('asks for the master password when the host wants it and shows the value after the grant', async () => {
    const { controller, presence } = openCard()
    vi.mocked(releaseItemField)
      .mockRejectedValueOnce(presenceRequired())
      .mockResolvedValueOnce('fictional-card-number')
    vi.mocked(grantPresence).mockResolvedValue(undefined)

    await controller.revealField('number')

    expect(get(presence.state)).toMatchObject({ open: true, intent: 'reveal-field' })
    expect(get(controller.state).revealed).toEqual({})

    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()

    expect(grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(get(presence.state).open).toBe(false)
    expect(get(controller.state).revealed).toEqual({ number: 'fictional-card-number' })
  })

  it('keeps showing nothing when the master password is wrong', async () => {
    const { controller, presence } = openCard()
    vi.mocked(releaseItemField).mockRejectedValue(presenceRequired())
    vi.mocked(grantPresence).mockRejectedValue(new Error('That master password does not open this vault.'))
    await controller.revealField('number')

    presence.state.patch({ secret: 'fictional wrong password' })
    await presence.confirm()

    expect(get(presence.state)).toMatchObject({ open: true, error: 'That master password does not open this vault.', secret: '' })
    expect(get(controller.state).revealed).toEqual({})
    expect(releaseItemField).toHaveBeenCalledTimes(1)
  })

  it('copies in the host and passes no value through the window', async () => {
    const { controller, feedback } = openCard()
    vi.mocked(copyItemField).mockResolvedValue(undefined)

    await controller.copyField('securityCode', 'Security code')

    expect(copyItemField).toHaveBeenCalledWith('card', 'card-1', 'securityCode')
    expect(get(feedback.state).notice?.title).toBe('Security code copied')
  })

  it('asks for the master password before a copy and copies after the grant', async () => {
    const { controller, presence } = openCard()
    vi.mocked(copyItemField).mockRejectedValueOnce(presenceRequired()).mockResolvedValueOnce(undefined)
    vi.mocked(grantPresence).mockResolvedValue(undefined)

    await controller.copyField('number', 'Card number')
    expect(get(presence.state)).toMatchObject({ open: true, intent: 'copy-field' })

    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()

    expect(copyItemField).toHaveBeenCalledTimes(2)
  })

  it('drops every revealed value when secrets are cleared', async () => {
    const { controller } = openCard()
    vi.mocked(releaseItemField).mockResolvedValue('fictional-card-number')
    await controller.revealField('number')

    controller.clearSecrets()

    expect(get(controller.state).revealed).toEqual({})
  })

  it('drops a value that arrives after the person selected another item', async () => {
    const { controller, stores } = openCard()
    vi.mocked(releaseItemField).mockImplementation(async () => {
      stores.selection.patch({ activeItemId: 'card-2' })
      return 'fictional-card-number'
    })

    await controller.revealField('number')

    expect(get(controller.state).revealed).toEqual({})
  })
})

describe('note lock', () => {
  const presenceRequired = () => new Error('presenceRequired')

  function openNote() {
    const context = harness()
    context.stores.selection.patch({ activeItemId: 'note-1', activeItemKind: 'secure_note' })
    context.stores.vault.patch({ status: { unlocked: true } } as never)
    return context
  }

  beforeEach(() => {
    vi.mocked(setSecureNoteLock).mockReset()
    vi.mocked(grantPresence).mockReset()
  })

  it('locks a note without asking for the master password', async () => {
    const { controller, presence } = openNote()
    vi.mocked(setSecureNoteLock).mockResolvedValue({ id: 'note-1', snapshot: { items: [], folders: [] } as never })

    await controller.setNoteLock(true)

    expect(setSecureNoteLock).toHaveBeenCalledWith('note-1', true)
    expect(get(presence.state).open).toBe(false)
  })

  it('asks for the master password before it removes a lock and retries once it is given', async () => {
    const { controller, presence } = openNote()
    vi.mocked(setSecureNoteLock)
      .mockRejectedValueOnce(presenceRequired())
      .mockResolvedValueOnce({ id: 'note-1', snapshot: { items: [], folders: [] } as never })
    vi.mocked(grantPresence).mockResolvedValue(undefined)

    await controller.setNoteLock(false)

    expect(get(presence.state)).toMatchObject({ open: true, intent: 'unlock-note' })

    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()

    expect(grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(setSecureNoteLock).toHaveBeenCalledTimes(2)
    expect(get(presence.state).open).toBe(false)
  })

  it('ignores a lock request when the open item is not a note', async () => {
    const { controller } = harness()
    await controller.setNoteLock(true)

    expect(setSecureNoteLock).not.toHaveBeenCalled()
  })
})


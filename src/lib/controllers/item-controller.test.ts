import { get } from 'svelte/store'
import { describe, expect, it, vi } from 'vitest'
import type { AppStores } from '../stores/app-stores'
import type { RecordKind } from '../item-fields'
import type { VaultSnapshot } from '../types'
import { searchItems } from '../vault'
import { createFeedbackController } from './feedback-controller'
import { createItemController, type RecordEditor } from './item-controller'
import type { LoginController } from './login-controller'

vi.mock('../vault', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../vault')>()
  return { ...actual, searchItems: vi.fn() }
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
  const controller = createItemController({ stores, feedback: createFeedbackController(), login, editors })
  return { controller, calls, stores }
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

  it('orders visible items by the ids Rust returned', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({
      snapshot: snapshotWith([
        { id: 'a', title: 'Alpha' },
        { id: 'b', title: 'Beta' },
        { id: 'c', title: 'Gamma' },
      ]),
    })
    vi.mocked(searchItems).mockResolvedValue(['c', 'a', 'b'])

    await controller.runSearch('zzz')

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

    await controller.runSearch('gamma')

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

    await controller.runSearch('gamma')

    expect(visibleIds(controller)).toEqual(['b', 'c'])
  })

  it('drops a stale response that resolves after a newer search', async () => {
    const { controller, stores } = harness()
    stores.vault.patch({
      snapshot: snapshotWith([
        { id: 'a', title: 'Alpha' },
        { id: 'b', title: 'Beta' },
        { id: 'c', title: 'Gamma' },
      ]),
    })
    let resolveStale: (ids: string[]) => void = () => {}
    vi.mocked(searchItems).mockImplementationOnce(() => new Promise((resolve) => { resolveStale = resolve }))
    const stale = controller.runSearch('zzz')
    vi.mocked(searchItems).mockResolvedValue(['c'])

    await controller.runSearch('yyy')
    resolveStale(['a'])
    await stale

    expect(visibleIds(controller)).toEqual(['c'])
  })
})

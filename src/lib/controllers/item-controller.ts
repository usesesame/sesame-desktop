import { derived } from 'svelte/store'
import { itemDetail, type ItemDetail, type ItemRecord, type RecordKind } from '../item-fields'
import type { AppStores } from '../stores/app-stores'
import type { ItemKind } from '../types'
import {
  bulkAssignFolder,
  copyToClipboard,
  getCard,
  getCustomRecord,
  getDocument,
  getIdentity,
  getSecureNote,
  getSoftwareLicense,
  getSshKey,
  getWifiNetwork,
  recordDiagnostic,
  recordItemUse,
  searchItems,
  setItemFavourite,
} from '../vault'
import { itemMatchesCollection, rememberRecent, sortCollectionItems } from '../vault-collections'
import { itemMatchesQuery, vaultItems, type VaultItem } from '../vault-items'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { LoginController } from './login-controller'

const recordLoaders: Record<RecordKind, (id: string) => Promise<ItemRecord>> = {
  identity: getIdentity,
  secure_note: getSecureNote,
  card: getCard,
  wifi_network: getWifiNetwork,
  ssh_key: getSshKey,
  software_license: getSoftwareLicense,
  document: getDocument,
  custom_record: getCustomRecord,
}

export interface RecordEditor {
  openNew: () => void
  openEditor: (id: string) => void | Promise<void>
  requestDelete: (id: string, title: string) => void
}

interface ItemControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  login: LoginController
  editors: Record<RecordKind, RecordEditor>
}

export function createItemController({ stores, feedback, login, editors }: ItemControllerOptions) {
  const { selection, settings, vault } = stores
  const state = controllerStore({
    detail: null as ItemDetail | null,
    loading: false,
    addMenuOpen: false,
    filterMenuOpen: false,
    /** Ids only; which fields matched a search is never held here. */
    searchMatchIds: new Set<string>(),
  })
  let detailRequestToken = 0
  let searchRequestToken = 0
  let loadedDetailKey = ''

  const allItems = derived(vault, ($vault) => vaultItems($vault.snapshot))

  const visibleItems = derived([allItems, selection, state], ([$allItems, $selection, $state]) => {
    const query = $selection.searchQuery.trim().toLowerCase()
    const matched = $allItems.filter((item) => {
      const securityFilter = $selection.securityFilter
      if (securityFilter && !item.issueKinds.includes(securityFilter)) return false
      if ($selection.categoryFilter && item.kind !== $selection.categoryFilter) return false
      if (query && !itemMatchesQuery(item, query) && !$state.searchMatchIds.has(item.id)) return false
      return itemMatchesCollection(item, $selection.collectionFilter)
    })
    return sortCollectionItems(matched, $selection.collectionFilter, $selection.sortMode)
  })

  const recentItems = derived([allItems, selection], ([$allItems, $selection]) => $selection.recentItemIds
    .map((id) => $allItems.find((item) => item.id === id))
    .filter((item): item is VaultItem => Boolean(item) && item!.id !== $selection.activeItemId))

  // An edit or a delete lands as a new snapshot, so the open record follows it.
  vault.subscribe(() => {
    const { activeItemId, activeItemKind } = selection.value()
    if (!activeItemId || !activeItemKind || activeItemKind === 'login' || !loadedDetailKey) return
    const key = detailKey(activeItemId)
    if (key === loadedDetailKey) return
    if (!key) {
      clearDetail()
      selection.patch({ activeItemId: null, activeItemKind: null })
      return
    }
    void select(activeItemId, activeItemKind)
  })

  function clearDetail() {
    detailRequestToken += 1
    loadedDetailKey = ''
    state.patch({ detail: null, loading: false })
  }

  function detailKey(id: string): string {
    const summary = vault.value().snapshot?.items.find((item) => item.id === id)
    return summary ? `${summary.id}:${summary.updatedAt}` : ''
  }

  async function select(id: string, kind: ItemKind) {
    if (kind === 'login') {
      clearDetail()
      selection.patch({ activeItemId: id, activeItemKind: 'login' })
      await login.selectEntry(id)
      selection.patch({ recentItemIds: rememberRecent(selection.value().recentItemIds, id) })
      return
    }
    login.clearSelection()
    detailRequestToken += 1
    // Cleared for the whole load so the snapshot watcher below cannot re-enter.
    loadedDetailKey = ''
    const requestToken = detailRequestToken
    selection.patch({ activeItemId: id, activeItemKind: kind })
    state.patch({ loading: true, detail: null })
    feedback.clearError()
    try {
      const record = await recordLoaders[kind](id)
      if (requestToken !== detailRequestToken || !vault.value().status.unlocked) return
      loadedDetailKey = detailKey(id)
      state.patch({ detail: itemDetail(kind, record), loading: false })
      selection.patch({ recentItemIds: rememberRecent(selection.value().recentItemIds, id) })
    } catch (error) {
      if (requestToken !== detailRequestToken) return
      state.patch({ loading: false })
      feedback.setError(error)
    }
  }

  async function markUsed(id: string) {
    try {
      vault.patch({ snapshot: await recordItemUse(id) })
    } catch {
      void recordDiagnostic('ui', 'handled_error')
    }
  }

  async function copy(value: string, label: string) {
    try {
      await copyToClipboard(value)
      const activeItemId = selection.value().activeItemId
      if (activeItemId) void markUsed(activeItemId)
      feedback.showNotice(`${label} copied`, `Clears after ${settings.value().clipboardClearSeconds} seconds if the clipboard has not changed.`)
    } catch (error) {
      void recordDiagnostic('clipboard', 'failed')
      feedback.setError(error)
    }
  }

  return {
    state,
    allItems,
    visibleItems,
    recentItems,
    select,
    copy,
    openNew(kind: ItemKind) {
      state.patch({ addMenuOpen: false })
      if (kind === 'login') {
        login.openNew()
        return
      }
      editors[kind].openNew()
    },
    async openEditor() {
      const { activeItemId, activeItemKind } = selection.value()
      if (!activeItemId || !activeItemKind) return
      if (activeItemKind === 'login') {
        login.openEditor()
        return
      }
      await editors[activeItemKind].openEditor(activeItemId)
    },
    requestDelete() {
      const { activeItemId, activeItemKind } = selection.value()
      const detail = state.value().detail
      if (!activeItemId || !activeItemKind || activeItemKind === 'login' || !detail) return
      editors[activeItemKind].requestDelete(activeItemId, detail.title)
    },
    async toggleFavourite(id: string, favourite: boolean) {
      try {
        vault.patch({ snapshot: await setItemFavourite(id, favourite) })
        const card = vault.value().loginCard
        if (card?.id === id) vault.patch({ loginCard: { ...card, favourite } })
        const detail = state.value().detail
        if (detail && selection.value().activeItemId === id) state.patch({ detail: { ...detail, favourite } })
        feedback.showNotice(favourite ? 'Added to favourites' : 'Removed from favourites', favourite ? 'This item now stays near the top.' : 'The item remains in its collection.')
      } catch (error) {
        feedback.setError(error)
      }
    },
    async moveToFolder(id: string, folderId?: string) {
      try {
        const snapshot = await bulkAssignFolder([id], folderId)
        vault.patch({ snapshot })
        const folder = snapshot.folders.find((candidate) => candidate.id === folderId)
        const card = vault.value().loginCard
        if (card?.id === id) vault.patch({ loginCard: { ...card, folderId: folder?.id, folder: folder?.name ?? '' } })
        const detail = state.value().detail
        if (detail && selection.value().activeItemId === id) state.patch({ detail: { ...detail, folderId: folder?.id } })
        feedback.showNotice('Collection updated', folder ? `Moved to ${folder.name}.` : 'Moved to Unfiled.')
      } catch (error) {
        feedback.setError(error)
      }
    },
    setCategory(categoryFilter: ItemKind | null) {
      selection.patch({ categoryFilter, securityFilter: null })
    },
    showCollection(collectionFilter: string | null) {
      selection.patch({ collectionFilter, securityFilter: null })
    },
    closeMenus() {
      state.patch({ addMenuOpen: false, filterMenuOpen: false })
    },
    toggleAddMenu(open?: boolean) {
      state.patch({ addMenuOpen: open ?? !state.value().addMenuOpen, filterMenuOpen: false })
    },
    toggleFilterMenu(open?: boolean) {
      state.patch({ filterMenuOpen: open ?? !state.value().filterMenuOpen, addMenuOpen: false })
    },
    async runSearch(query: string) {
      selection.patch({ searchQuery: query })
      searchRequestToken += 1
      const requestToken = searchRequestToken
      if (!query.trim()) {
        state.patch({ searchMatchIds: new Set() })
        return
      }
      try {
        const ids = await searchItems(query)
        if (requestToken !== searchRequestToken) return
        state.patch({ searchMatchIds: new Set(ids) })
      } catch {
        // A failed search narrows the results rather than emptying them.
        if (requestToken === searchRequestToken) state.patch({ searchMatchIds: new Set() })
      }
    },
    clearSearch() {
      searchRequestToken += 1
      selection.patch({ searchQuery: '' })
      state.patch({ searchMatchIds: new Set() })
    },
    clearSelection() {
      clearDetail()
      login.clearSelection()
      selection.patch({ activeItemId: null, activeItemKind: null })
    },
    clearSecrets() {
      detailRequestToken += 1
      searchRequestToken += 1
      state.set({ detail: null, loading: false, addMenuOpen: false, filterMenuOpen: false, searchMatchIds: new Set() })
      selection.patch({ activeItemId: null, activeItemKind: null, recentItemIds: [] })
    },
  }
}

export type ItemController = ReturnType<typeof createItemController>

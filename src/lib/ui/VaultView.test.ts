/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { VaultItem } from '../vault-items'
import VaultView from './VaultView.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

function item(id: string, title: string, overrides: Partial<VaultItem> = {}): VaultItem {
  return { id, kind: 'login', title, subtitle: '', initials: 'F', folder: '', favourite: false, updatedAt: 1, tags: [], issueKinds: [], ...overrides }
}

function vaultProps(overrides: Record<string, unknown> = {}) {
  const items = [item('login-a', 'Northwind'), item('login-b', 'Contoso'), item('login-c', 'Fabrikam')]
  return {
    allItems: items,
    visibleItems: items,
    recentItems: [],
    onSelectItem: vi.fn(),
    onAddItem: vi.fn(),
    onToggleAddMenu: vi.fn(),
    onToggleFilterMenu: vi.fn(),
    onOpenNewLogin: vi.fn(),
    onImport: vi.fn(),
    onClearSearch: vi.fn(),
    onSearch: vi.fn(),
    onSetSortMode: vi.fn(),
    onClearSecurityFilter: vi.fn(),
    onSetCategory: vi.fn(),
    onShowCollection: vi.fn(),
    onOrganizeFolders: vi.fn(),
    onOpenContextMenu: vi.fn(),
    onOpenLoginEditor: vi.fn(),
    onOpenItemEditor: vi.fn(),
    onDeleteItem: vi.fn(),
    onMoveItem: vi.fn(),
    onItemCopy: vi.fn(),
    onOpenRecoveryNotApplicable: vi.fn(),
    onToggleBreachCheck: vi.fn(),
    onRunBreachCheck: vi.fn(),
    onRevealPassword: async () => {},
    onCopyPassword: vi.fn(),
    onConfirmPasswordPresence: vi.fn(),
    onCancelPasswordPresence: vi.fn(),
    onStartAutoType: vi.fn(),
    onCancelAutoType: vi.fn(),
    onCopy: vi.fn(),
    onOpenWebsite: vi.fn(),
    onGoSecurity: vi.fn(),
    onAddWebsite: vi.fn(),
    onOpenDuplicateReview: vi.fn(),
    onToggleFavourite: vi.fn(),
    onStartMultiSelect: vi.fn(),
    onToggleMultiSelect: vi.fn(),
    onSelectVisible: vi.fn(),
    onSetBulkFolderId: vi.fn(),
    onBulkMove: vi.fn(),
    onBulkFavourite: vi.fn(),
    onBulkDelete: vi.fn(),
    onSetBulkTag: vi.fn(),
    onBulkTag: vi.fn(),
    onCancelMultiSelect: vi.fn(),
    focusResultsToken: 0,
    ...overrides,
  }
}

function renderVault(overrides: Record<string, unknown> = {}) {
  const stores = createAppStores()
  const props = vaultProps(overrides)
  const rendered = render(VaultView, {
    props,
    context: new Map([[APP_STORES, stores]]),
  } as never)
  return { rendered, stores, props }
}

function rowButtons(container: HTMLElement): HTMLButtonElement[] {
  return [...container.querySelectorAll<HTMLButtonElement>('.entry-row-main')]
}

test('the bulk toolbar forwards move, favourite, and delete actions', async () => {
  const onBulkMove = vi.fn()
  const onBulkFavourite = vi.fn()
  const onBulkDelete = vi.fn()
  renderVault({ multiSelect: true, selectedIds: ['login-a', 'login-b'], onBulkMove, onBulkFavourite, onBulkDelete })
  await Promise.resolve()

  await fireEvent.click(screen.getByRole('button', { name: 'Move' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Favourite' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

  expect(onBulkMove).toHaveBeenCalledOnce()
  expect(onBulkFavourite).toHaveBeenCalledOnce()
  expect(onBulkDelete).toHaveBeenCalledOnce()
})

test('the bulk tag control reports typed text and sends the tag', async () => {
  const onSetBulkTag = vi.fn()
  const onBulkTag = vi.fn()
  renderVault({ multiSelect: true, selectedIds: ['login-a'], bulkTag: 'Travel', onSetBulkTag, onBulkTag })
  await Promise.resolve()

  const input = screen.getByLabelText('Tag to add to the selected items') as HTMLInputElement
  expect(input.value).toBe('Travel')
  await fireEvent.click(screen.getByRole('button', { name: 'Tag' }))
  expect(onBulkTag).toHaveBeenCalledOnce()

  await fireEvent.input(input, { target: { value: 'Work' } })
  expect(onSetBulkTag).toHaveBeenCalledWith('Work')
})

test('the bulk tag button waits for a selected item and a tag', async () => {
  renderVault({ multiSelect: true, selectedIds: [], bulkTag: 'Travel' })
  await Promise.resolve()
  expect((screen.getByRole('button', { name: 'Tag' }) as HTMLButtonElement).disabled).toBe(true)

  cleanup()
  renderVault({ multiSelect: true, selectedIds: ['login-a'], bulkTag: '   ' })
  await Promise.resolve()
  expect((screen.getByRole('button', { name: 'Tag' }) as HTMLButtonElement).disabled).toBe(true)
})

test('arrow keys move focus and selection through the visible rows', async () => {
  const onSelectItem = vi.fn()
  const { rendered } = renderVault({ onSelectItem })
  await Promise.resolve()
  const rows = rowButtons(rendered.container)

  rows[0].focus()
  await fireEvent.keyDown(rows[0], { key: 'ArrowDown' })
  expect(document.activeElement).toBe(rows[1])
  expect(onSelectItem).toHaveBeenLastCalledWith('login-b', 'login')
  await fireEvent.keyDown(rows[1], { key: 'ArrowDown' })
  expect(document.activeElement).toBe(rows[2])
  await fireEvent.keyDown(rows[2], { key: 'ArrowUp' })
  expect(document.activeElement).toBe(rows[1])
  expect(onSelectItem).toHaveBeenLastCalledWith('login-b', 'login')
  await fireEvent.keyDown(rows[1], { key: 'End' })
  expect(document.activeElement).toBe(rows[2])
  expect(onSelectItem).toHaveBeenLastCalledWith('login-c', 'login')
  await fireEvent.keyDown(rows[2], { key: 'Home' })
  expect(document.activeElement).toBe(rows[0])
})

test('arrow keys in multi-select mode move focus without toggling selection', async () => {
  const onSelectItem = vi.fn()
  const onToggleMultiSelect = vi.fn()
  const { rendered } = renderVault({ multiSelect: true, selectedIds: ['login-a'], onSelectItem, onToggleMultiSelect })
  await Promise.resolve()
  const rows = rowButtons(rendered.container)

  rows[0].focus()
  await fireEvent.keyDown(rows[0], { key: 'ArrowDown' })

  expect(document.activeElement).toBe(rows[1])
  expect(onSelectItem).not.toHaveBeenCalled()
  expect(onToggleMultiSelect).not.toHaveBeenCalled()
})

test('an arrow key on a select checkbox leaves focus and selection alone', async () => {
  const onToggleMultiSelect = vi.fn()
  const { rendered } = renderVault({ multiSelect: true, selectedIds: ['login-a'], onToggleMultiSelect })
  await Promise.resolve()
  const box = rendered.container.querySelector<HTMLInputElement>('.entry-select-box')
  expect(box).toBeTruthy()
  box!.focus()

  await fireEvent.keyDown(box!, { key: 'ArrowDown' })

  expect(document.activeElement).toBe(box)
  expect(onToggleMultiSelect).not.toHaveBeenCalled()
})

test('the context menu key still opens the row menu', async () => {
  const onOpenContextMenu = vi.fn()
  const { rendered } = renderVault({ onOpenContextMenu })
  await Promise.resolve()
  const rows = rowButtons(rendered.container)

  await fireEvent.keyDown(rows[0], { key: 'ContextMenu' })

  expect(onOpenContextMenu).toHaveBeenCalledOnce()
})

test('the focus results token moves focus to the first row', async () => {
  const onSelectItem = vi.fn()
  const { rendered } = renderVault({ onSelectItem })
  await Promise.resolve()
  const rows = rowButtons(rendered.container)

  await rendered.rerender({ focusResultsToken: 1 } as never)
  await vi.waitFor(() => expect(document.activeElement).toBe(rows[0]))
  expect(onSelectItem).toHaveBeenLastCalledWith('login-a', 'login')
})

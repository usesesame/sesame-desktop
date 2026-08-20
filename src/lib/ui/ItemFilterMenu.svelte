<script lang="ts">
  import { tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import { handleMenuItemKeydown, handleMenuTriggerKeydown, menuItemsIn } from '../menu-keys'
  import type { Folder, ItemKind } from '../types'
  import { FAVOURITES_FILTER, RECENT_FILTER, tagFilter, tagFromFilter, UNFILED_FILTER } from '../vault-collections'
  import { ITEM_KINDS, itemKindMeta, type VaultItem } from '../vault-items'

  export let open = false
  export let items: VaultItem[] = []
  export let folders: Folder[] = []
  export let tags: string[] = []
  export let categoryFilter: ItemKind | null = null
  export let collectionFilter: string | null = null
  export let onToggle: (open?: boolean) => void
  export let onSetCategory: (kind: ItemKind | null) => void
  export let onShowCollection: (filter: string | null) => void
  export let onOrganizeFolders: () => void

  let container: HTMLDivElement
  let trigger: HTMLButtonElement

  $: counts = ITEM_KINDS.map((kind) => ({ ...kind, count: items.filter((item) => item.kind === kind.id).length })).filter((kind) => kind.count > 0)
  $: favouriteCount = items.filter((item) => item.favourite).length
  $: recentCount = items.filter((item) => item.lastUsedAt).length
  $: unfiledCount = items.filter((item) => !item.folderId).length
  $: activeTag = tagFromFilter(collectionFilter)
  $: collectionLabel = collectionFilter === null
    ? null
    : collectionFilter === FAVOURITES_FILTER
      ? 'Favourites'
      : collectionFilter === RECENT_FILTER
        ? 'Recently used'
        : activeTag !== null
          ? activeTag
          : collectionFilter === UNFILED_FILTER
            ? 'Unfiled'
            : folders.find((folder) => folder.id === collectionFilter)?.name ?? 'Collection'
  $: categoryLabel = categoryFilter ? itemKindMeta(categoryFilter).plural : null
  $: summary = [categoryLabel, collectionLabel].filter(Boolean).join(' · ') || 'All items'
  $: filtered = Boolean(categoryFilter) || collectionFilter !== null

  function close(returnFocus: boolean) {
    onToggle(false)
    if (returnFocus) trigger?.focus()
  }

  async function openWithFocus(index: number) {
    onToggle(true)
    await tick()
    menuItemsIn(container).at(index)?.focus()
  }

  function choose(action: () => void) {
    action()
    close(true)
  }

  function folderCount(folderId: string) {
    return items.filter((item) => item.folderId === folderId).length
  }

  function tagCount(tag: string) {
    return items.filter((item) => item.tags.some((candidate) => candidate.toLowerCase() === tag.toLowerCase())).length
  }

  function handleOutside(event: MouseEvent) {
    if (open && container && !container.contains(event.target as Node)) close(false)
  }
</script>

<svelte:window on:mousedown={handleOutside} />

<div class="filter-menu" bind:this={container}>
  <button
    bind:this={trigger}
    type="button"
    class="sort-select-trigger filter-trigger"
    class:filtered
    aria-haspopup="menu"
    aria-expanded={open}
    aria-controls="item-filter-options"
    aria-label={`Filter items, currently ${summary}`}
    on:click={() => onToggle()}
    on:keydown={(event) => handleMenuTriggerKeydown(event, (index) => void openWithFocus(index))}
  >
    <Icon name="folder" size={14} />
    <span>Filter</span>
    <svg viewBox="0 0 12 12" aria-hidden="true"><path d="m3 4.5 3 3 3-3" /></svg>
  </button>

  {#if open}
    <div id="item-filter-options" class="filter-options" role="menu" aria-label="Filter items">
      <p class="filter-group-label">Types</p>
      <button type="button" role="menuitemradio" aria-checked={categoryFilter === null} tabindex="-1" on:click={() => choose(() => onSetCategory(null))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
        <Icon name="vault" size={14} /><span>All items</span><small>{items.length}</small>
      </button>
      {#each counts as kind (kind.id)}
        <button type="button" role="menuitemradio" aria-checked={categoryFilter === kind.id} tabindex="-1" on:click={() => choose(() => onSetCategory(kind.id))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
          <Icon name={kind.icon} size={14} /><span>{kind.plural}</span><small>{kind.count}</small>
        </button>
      {/each}

      <p class="filter-group-label">Collections</p>
      <button type="button" role="menuitemradio" aria-checked={collectionFilter === null} tabindex="-1" on:click={() => choose(() => onShowCollection(null))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
        <Icon name="folder" size={14} /><span>All collections</span><small>{items.length}</small>
      </button>
      <button type="button" role="menuitemradio" aria-checked={collectionFilter === FAVOURITES_FILTER} tabindex="-1" on:click={() => choose(() => onShowCollection(FAVOURITES_FILTER))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
        <span class="collection-star" aria-hidden="true">★</span><span>Favourites</span><small>{favouriteCount}</small>
      </button>
      <button type="button" role="menuitemradio" aria-checked={collectionFilter === RECENT_FILTER} tabindex="-1" on:click={() => choose(() => onShowCollection(RECENT_FILTER))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
        <Icon name="refresh" size={14} /><span>Recently used</span><small>{recentCount}</small>
      </button>
      {#each folders as folder (folder.id)}
        <button type="button" role="menuitemradio" aria-checked={collectionFilter === folder.id} tabindex="-1" on:click={() => choose(() => onShowCollection(folder.id))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
          <Icon name="folder" size={14} /><span>{folder.name}</span><small>{folderCount(folder.id)}</small>
        </button>
      {/each}
      <button type="button" role="menuitemradio" aria-checked={collectionFilter === UNFILED_FILTER} tabindex="-1" on:click={() => choose(() => onShowCollection(UNFILED_FILTER))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
        <Icon name="folder-minus" size={14} /><span>Unfiled</span><small>{unfiledCount}</small>
      </button>

      {#if tags.length}
        <p class="filter-group-label">Tags</p>
        {#each tags as tag (tag)}
          <button type="button" role="menuitemradio" aria-checked={activeTag === tag} tabindex="-1" on:click={() => choose(() => onShowCollection(tagFilter(tag)))} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
            <Icon name="custom" size={14} /><span>{tag}</span><small>{tagCount(tag)}</small>
          </button>
        {/each}
      {/if}

      <div class="filter-menu-footer">
        <button type="button" role="menuitem" tabindex="-1" on:click={() => choose(onOrganizeFolders)} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
          <Icon name="settings" size={14} /><span>Organize folders</span>
        </button>
      </div>
    </div>
  {/if}
</div>

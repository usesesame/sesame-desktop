<script lang="ts">
  import { onDestroy, tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import { issueChipLabel, issueChips, issueFilterLabel, issueKindLabels } from '../issue-kinds'
  import type { ItemDetail as ItemDetailShape } from '../item-fields'
  import { platformCapabilities } from '../platform'
  import { useAppStores } from '../stores/app-stores'
  import type { BreachCheckResult, ItemKind, VaultPane } from '../types'
  import { FAVOURITES_FILTER, RECENT_FILTER, SORT_MODES, sortModeLabels, tagFilter, tagFromFilter } from '../vault-collections'
  import { itemKindIcon, itemKindLabel, itemKindMeta, itemTags, type VaultItem } from '../vault-items'
  import AddItemMenu from './AddItemMenu.svelte'
  import ItemFilterMenu from './ItemFilterMenu.svelte'
  import ItemDetail from './ItemDetail.svelte'
  import PanelResizer from './PanelResizer.svelte'
  import WebsiteIcon from './WebsiteIcon.svelte'
  import { PANEL_WIDTH_LIMITS, readPanelWidths, storePanelWidths } from '../preferences'

  const PASSWORD_REVEAL_TIMEOUT_MS = 30_000

  export let allItems: VaultItem[] = []
  export let visibleItems: VaultItem[] = []
  export let recentItems: VaultItem[] = []
  export let itemDetail: ItemDetailShape | null = null
  export let itemLoading = false
  export let addMenuOpen = false
  export let filterMenuOpen = false
  export let focusSearchToken = 0
  export let passwordVisible = false
  export let siteIconsEnabled = false
  export let totpRemaining = 0
  export let totpProgress = '0%'
  export let totpRefreshIssue = false
  export let multiSelect = false
  export let selectedIds: string[] = []
  export let bulkFolderId = ''
  export let recoveryActionWorking = false
  export let onSelectItem: (id: string, kind: ItemKind) => void
  export let onAddItem: (kind: ItemKind) => void
  export let onToggleAddMenu: (open?: boolean) => void
  export let onToggleFilterMenu: (open?: boolean) => void
  export let onOpenNewLogin: (password?: string) => void
  export let onImport: () => void
  export let onClearSearch: () => void
  export let onSearch: (query: string) => void
  export let onSetSortMode: (mode: string) => void
  export let onClearSecurityFilter: () => void
  export let onSetCategory: (kind: ItemKind | null) => void
  export let onShowCollection: (filter: string | null) => void
  export let onOrganizeFolders: () => void
  export let onOpenContextMenu: (position: { x: number; y: number }, id: string) => void
  export let onOpenLoginEditor: () => void
  export let onOpenItemEditor: () => void
  export let onDeleteItem: () => void
  export let onMoveItem: (folderId?: string) => void
  export let onItemCopy: (value: string, label: string) => void
  export let onOpenRecoveryNotApplicable: () => void
  export let onFixWeakPassword: () => void
  export let breachCheckOpen = false
  export let breachCheckWorking = false
  export let breachCheckResult: BreachCheckResult | null = null
  export let breachCheckError = ''
  export let onToggleBreachCheck: () => void
  export let onRunBreachCheck: () => void
  export let autoTypeEntryId = ''
  export let autoTypeCountdown = 0
  export let onStartAutoType: () => void
  export let onCancelAutoType: () => void
  export let onCopy: (value: string, label: string) => void
  export let onOpenWebsite: (url: string) => void
  export let onGoSecurity: () => void
  export let onAddWebsite: () => void
  export let onOpenDuplicateReview: () => void
  export let onToggleFavourite: (id: string, favourite: boolean) => void
  export let onStartMultiSelect: (id?: string) => void
  export let onToggleMultiSelect: (id: string, selected: boolean) => void
  export let onSelectVisible: (ids: string[]) => void
  export let onSetBulkFolderId: (folderId: string) => void
  export let onBulkMove: () => void
  export let onBulkFavourite: () => void
  export let onBulkDelete: () => void
  export let onCancelMultiSelect: () => void

  const { selection, vault } = useAppStores()
  $: snapshotEntries = $vault.snapshot?.entries ?? []
  $: folders = $vault.snapshot?.folders ?? []
  $: selectedEntry = snapshotEntries.find((entry) => entry.id === $selection.activeItemId) ?? null
  $: selectedSet = new Set(selectedIds)
  $: allVisibleSelected = visibleItems.length > 0 && visibleItems.every((item) => selectedSet.has(item.id))
  $: selectedItems = allItems.filter((item) => selectedSet.has(item.id))
  $: allSelectedFavourite = selectedItems.length > 0 && selectedItems.every((item) => item.favourite)
  $: allSelectedLogins = selectedItems.length > 0 && selectedItems.every((item) => item.kind === 'login')
  $: tags = itemTags(allItems)
  $: activeFolder = folders.find((folder) => folder.id === $selection.collectionFilter)
  $: activeTag = tagFromFilter($selection.collectionFilter)
  $: collectionHeading = $selection.collectionFilter === null
    ? 'All items'
    : $selection.collectionFilter === FAVOURITES_FILTER
      ? 'Favourites'
      : $selection.collectionFilter === RECENT_FILTER
        ? 'Recently used'
        : activeTag !== null
          ? activeTag
          : $selection.collectionFilter === ''
            ? 'Unfiled'
            : activeFolder?.name ?? 'Collection'
  $: listHeading = $selection.securityFilter
    ? 'Security review'
    : $selection.categoryFilter && $selection.collectionFilter === null
      ? itemKindMeta($selection.categoryFilter).plural
      : collectionHeading
  $: activeIssue = $selection.securityFilter
  $: activePasswordIssues = selectedEntry?.passwordIssues.filter((issue) => issue.kind === activeIssue) ?? []

  let panelWidths = readPanelWidths()
  const commitPanelWidths = () => storePanelWidths(panelWidths)
  let pane: VaultPane = $selection.activeItemId ? 'detail' : 'list'
  let lastActiveItemId = $selection.activeItemId

  $: if ($selection.activeItemId !== lastActiveItemId) {
    lastActiveItemId = $selection.activeItemId
    pane = $selection.activeItemId ? 'detail' : 'list'
  }

  let searchInput: HTMLInputElement
  let passwordRevealTimer: ReturnType<typeof setTimeout> | null = null
  let sortMenuOpen = false
  let sortContainer: HTMLElement
  let sortButton: HTMLButtonElement
  let folderMenuOpen = false
  let folderContainer: HTMLElement
  let folderButton: HTMLButtonElement

  function sortOptionButtons() {
    return [...(sortContainer?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? [])]
  }

  function closeSortMenu(returnFocus: boolean) {
    sortMenuOpen = false
    if (returnFocus) sortButton?.focus()
  }

  function chooseSortMode(mode: string) {
    onSetSortMode(mode)
    closeSortMenu(true)
  }

  function handleSortOutside(event: MouseEvent) {
    if (sortMenuOpen && sortContainer && !sortContainer.contains(event.target as Node)) closeSortMenu(false)
  }

  function handleSortTriggerKeydown(event: KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      sortMenuOpen = true
      const options = sortOptionButtons()
      const selected = options.find((option) => option.getAttribute('aria-selected') === 'true')
      ;(selected ?? options[0])?.focus()
    }
  }

  function handleSortOptionKeydown(event: KeyboardEvent) {
    const options = sortOptionButtons()
    const current = Math.max(0, options.indexOf(event.currentTarget as HTMLButtonElement))
    let next: number | null = null
    if (event.key === 'ArrowDown') next = (current + 1) % options.length
    if (event.key === 'ArrowUp') next = (current - 1 + options.length) % options.length
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = options.length - 1
    if (next !== null) {
      event.preventDefault()
      options[next]?.focus()
      return
    }
    if (event.key === 'Escape') {
      event.preventDefault()
      closeSortMenu(true)
      return
    }
    if (event.key === 'Tab') closeSortMenu(false)
  }

  function folderOptionButtons() {
    return [...(folderContainer?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? [])]
  }

  function closeFolderMenu(returnFocus: boolean) {
    folderMenuOpen = false
    if (returnFocus) folderButton?.focus()
  }

  function chooseBulkFolder(id: string) {
    onSetBulkFolderId(id)
    closeFolderMenu(true)
  }

  function handleFolderOutside(event: MouseEvent) {
    if (folderMenuOpen && folderContainer && !folderContainer.contains(event.target as Node)) closeFolderMenu(false)
  }

  function handleFolderTriggerKeydown(event: KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      folderMenuOpen = true
      const options = folderOptionButtons()
      const selected = options.find((option) => option.getAttribute('aria-selected') === 'true')
      ;(selected ?? options[0])?.focus()
    }
  }

  function handleFolderOptionKeydown(event: KeyboardEvent) {
    const options = folderOptionButtons()
    const current = Math.max(0, options.indexOf(event.currentTarget as HTMLButtonElement))
    let next: number | null = null
    if (event.key === 'ArrowDown') next = (current + 1) % options.length
    if (event.key === 'ArrowUp') next = (current - 1 + options.length) % options.length
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = options.length - 1
    if (next !== null) {
      event.preventDefault()
      options[next]?.focus()
      return
    }
    if (event.key === 'Escape') {
      event.preventDefault()
      closeFolderMenu(true)
      return
    }
    if (event.key === 'Tab') closeFolderMenu(false)
  }

  $: bulkFolderLabel = bulkFolderId
    ? folders.find((folder) => folder.id === bulkFolderId)?.name ?? 'Unfiled'
    : 'Unfiled'

  function clearPasswordRevealTimer() {
    if (passwordRevealTimer) clearTimeout(passwordRevealTimer)
    passwordRevealTimer = null
  }

  function setPasswordVisible(visible: boolean) {
    clearPasswordRevealTimer()
    passwordVisible = visible
    if (visible) passwordRevealTimer = setTimeout(() => {
      passwordVisible = false
      passwordRevealTimer = null
    }, PASSWORD_REVEAL_TIMEOUT_MS)
  }

  $: if ($selection.collectionFilter === RECENT_FILTER) sortMenuOpen = false
  $: if ($selection.activeItemId) clearPasswordRevealTimer()
  onDestroy(clearPasswordRevealTimer)

  function keyboardContextMenu(event: KeyboardEvent, item: VaultItem) {
    if (item.kind !== 'login') return
    if (event.key !== 'ContextMenu' && !(event.shiftKey && event.key === 'F10')) return
    event.preventDefault()
    const bounds = (event.currentTarget as HTMLElement).getBoundingClientRect()
    onOpenContextMenu({ x: bounds.left + 24, y: bounds.top + 24 }, item.id)
  }

  function activateRow(item: VaultItem) {
    if (multiSelect) onToggleMultiSelect(item.id, !selectedSet.has(item.id))
    else {
      onSelectItem(item.id, item.kind)
      pane = 'detail'
    }
  }

  function selectRecent(item: VaultItem) {
    onSelectItem(item.id, item.kind)
    pane = 'detail'
  }

  let lastFocusSearchToken = 0
  $: if (focusSearchToken !== lastFocusSearchToken) {
    lastFocusSearchToken = focusSearchToken
    void tick().then(() => {
      searchInput?.focus()
      searchInput?.select()
    })
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    const target = event.target as HTMLElement | null
    if (target?.closest('[role="dialog"]')) return
    if (target === searchInput && event.key === 'Escape' && $selection.searchQuery) {
      event.preventDefault()
      onClearSearch()
      return
    }
    if (event.key === 'Escape' && autoTypeCountdown > 0) {
      event.preventDefault()
      onCancelAutoType()
      return
    }
    const editing = target?.matches('input, textarea, select, [contenteditable="true"]')
    if (!multiSelect || editing) return
    if (event.key === 'Escape') {
      event.preventDefault()
      onCancelMultiSelect()
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
      event.preventDefault()
      onSelectVisible(allVisibleSelected ? [] : visibleItems.map((item) => item.id))
    }
  }

  function clearEmptyStateFilters() {
    onClearSearch()
    onClearSecurityFilter()
    onSetCategory(null)
    if ($selection.collectionFilter !== null) onShowCollection(null)
  }
</script>

<svelte:window on:keydown={handleWindowKeydown} on:mousedown={handleSortOutside} on:mousedown={handleFolderOutside} />

<header class="vault-view-header">
  <div><h2>Vault</h2></div>
  <button type="button" class="security-summary-button" on:click={onGoSecurity}>
    <Icon name="shield-alert" size={15} />
    {#if ($vault.snapshot?.security.needsAttention ?? 0) > 0}
      {$vault.snapshot?.security.needsAttention} {$vault.snapshot?.security.needsAttention === 1 ? 'finding' : 'findings'}
    {:else}
      Checkup
    {/if}
  </button>
</header>

{#if !allItems.length}
  <section class="empty-workspace">
    <img class="empty-brand size-md" src="/favicon.svg" alt="" width="512" height="512" />
    <h2>Bring in your logins.</h2>
    <p>Import an export from another password manager. Sesame reads it on this device.</p>
    <button class="primary-button" on:click={onImport}>Choose export file</button>
    <button class="text-button empty-add" on:click={() => onOpenNewLogin()}>Add a login instead</button>
  </section>
{:else}
  <div class="vault-layout pane-{pane}" style="--vault-list-width: {panelWidths.list}px;">
    <section class="entry-list-panel" aria-label="Saved items">
      <div class="panel-heading">
        <div>
          <h2>{listHeading}</h2>
          <p>{visibleItems.length} {visibleItems.length === 1 ? 'item' : 'items'}</p>
        </div>
        <div class="panel-heading-actions">
          <button type="button" class="select-logins-button" class:active={multiSelect} on:click={() => multiSelect ? onCancelMultiSelect() : onStartMultiSelect()}>{multiSelect ? 'Done' : 'Select'}</button>
          <AddItemMenu open={addMenuOpen} onToggle={onToggleAddMenu} onAdd={onAddItem} {onImport} />
        </div>
      </div>

      <label class="search-box"><Icon name="search" size={15} /><input bind:this={searchInput} value={$selection.searchQuery} on:input={(event) => onSearch(event.currentTarget.value)} placeholder="Search every item…" aria-label="Search every saved item" aria-keyshortcuts="Control+K Meta+K /" />{#if !$selection.searchQuery}<kbd aria-hidden="true">/</kbd>{:else}<button type="button" aria-label="Clear search" on:click={onClearSearch}>×</button>{/if}</label>

      <div class="vault-list-tools">
        <ItemFilterMenu
          open={filterMenuOpen}
          items={allItems}
          {folders}
          {tags}
          categoryFilter={$selection.categoryFilter}
          collectionFilter={$selection.collectionFilter}
          onToggle={onToggleFilterMenu}
          {onSetCategory}
          {onShowCollection}
          {onOrganizeFolders}
        />
        <div class="sort-control" bind:this={sortContainer}>
          <span id="sort-control-label" class="sr-only">Sort items</span>
          <button
            bind:this={sortButton}
            type="button"
            class="sort-select-trigger"
            aria-haspopup="listbox"
            aria-labelledby="sort-control-label"
            aria-controls="sort-control-options"
            aria-expanded={sortMenuOpen}
            disabled={$selection.collectionFilter === RECENT_FILTER}
            on:click={() => (sortMenuOpen = !sortMenuOpen)}
            on:keydown={handleSortTriggerKeydown}
          >
            <span>{sortModeLabels[$selection.sortMode]}</span>
            <svg viewBox="0 0 12 12" aria-hidden="true"><path d="m3 4.5 3 3 3-3" /></svg>
          </button>
          {#if sortMenuOpen}
            <div id="sort-control-options" class="sort-menu" role="listbox" aria-labelledby="sort-control-label">
              {#each SORT_MODES as mode (mode)}
                <button type="button" class:selected={mode === $selection.sortMode} role="option" aria-selected={mode === $selection.sortMode} tabindex="-1" on:click={() => chooseSortMode(mode)} on:keydown={handleSortOptionKeydown}>{sortModeLabels[mode]}</button>
              {/each}
            </div>
          {/if}
        </div>
      </div>

      {#if activeIssue || $selection.categoryFilter || $selection.collectionFilter !== null}
        <div class="active-filters">
          {#if activeIssue}<button type="button" class="active-filter" on:click={onClearSecurityFilter}>{issueFilterLabel(activeIssue)} <span aria-hidden="true">×</span></button>{/if}
          {#if $selection.categoryFilter}<button type="button" class="active-filter" on:click={() => onSetCategory(null)}>{itemKindMeta($selection.categoryFilter).plural} <span aria-hidden="true">×</span></button>{/if}
          {#if $selection.collectionFilter !== null}<button type="button" class="active-filter" on:click={() => onShowCollection(null)}>{collectionHeading} <span aria-hidden="true">×</span></button>{/if}
        </div>
      {/if}

      {#if multiSelect}
        <div class="bulk-toolbar" role="region" aria-label="Bulk item actions">
          <label class="bulk-select-all"><input type="checkbox" checked={allVisibleSelected} aria-label="Select all visible items" on:change={() => onSelectVisible(allVisibleSelected ? [] : visibleItems.map((item) => item.id))} /><span>{selectedIds.length} selected</span></label>
          <div class="bulk-destination">
            <div class="sort-control" bind:this={folderContainer}>
              <button
                bind:this={folderButton}
                type="button"
                class="sort-select-trigger"
                aria-haspopup="listbox"
                aria-expanded={folderMenuOpen}
                aria-label="Destination collection"
                on:click={() => (folderMenuOpen = !folderMenuOpen)}
                on:keydown={handleFolderTriggerKeydown}
              >
                <span>{bulkFolderLabel}</span>
                <svg viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 4.5 6 8l3.5-3.5" /></svg>
              </button>
              {#if folderMenuOpen}
                <div class="sort-menu" role="listbox" aria-label="Destination collection">
                  <button type="button" class:selected={!bulkFolderId} role="option" aria-selected={!bulkFolderId} tabindex="-1" on:click={() => chooseBulkFolder('')} on:keydown={handleFolderOptionKeydown}>Unfiled</button>
                  {#each folders as folder (folder.id)}
                    <button type="button" class:selected={bulkFolderId === folder.id} role="option" aria-selected={bulkFolderId === folder.id} tabindex="-1" on:click={() => chooseBulkFolder(folder.id)} on:keydown={handleFolderOptionKeydown}>{folder.name}</button>
                  {/each}
                </div>
              {/if}
            </div>
            <button type="button" class="secondary-button bulk-move-button" disabled={!selectedIds.length} on:click={onBulkMove}>Move</button>
          </div>
          <div class="bulk-toolbar-actions">
            <button type="button" class="secondary-button" disabled={!selectedIds.length} on:click={onBulkFavourite}>{allSelectedFavourite ? 'Unfavourite' : 'Favourite'}</button>
            <button type="button" class="editor-delete" disabled={!allSelectedLogins} title={allSelectedLogins ? 'Delete the selected logins' : 'Deleting in bulk covers logins only'} on:click={onBulkDelete}>Delete</button>
          </div>
        </div>
      {/if}

      {#if visibleItems.length}
        <div class="entry-list" role="list" aria-label={multiSelect ? 'Select items' : 'Saved items'}>
          {#each visibleItems as item (item.id)}
            <div class="entry-row" class:selected={$selection.activeItemId === item.id && !multiSelect} class:multi-selected={selectedSet.has(item.id)} role="listitem" on:contextmenu|preventDefault={(event) => !multiSelect && item.kind === 'login' && onOpenContextMenu({ x: event.clientX, y: event.clientY }, item.id)}>
              {#if multiSelect}<input class="entry-select-box" type="checkbox" checked={selectedSet.has(item.id)} aria-label={`Select ${item.title}`} on:change={(event) => onToggleMultiSelect(item.id, event.currentTarget.checked)} />{/if}
              <button type="button" class="entry-row-main" aria-current={!multiSelect && $selection.activeItemId === item.id ? 'true' : undefined} aria-pressed={multiSelect ? selectedSet.has(item.id) : undefined} on:click={() => activateRow(item)} on:keydown={(event) => !multiSelect && keyboardContextMenu(event, item)}>
                <span class="entry-avatar">
                  {#if item.kind === 'login'}<WebsiteIcon site={item.subtitle} initials={item.initials} enabled={siteIconsEnabled} />{:else}<Icon name={itemKindIcon(item.kind)} size={15} />{/if}
                </span>
                <span class="entry-title"><strong>{item.title}</strong><small>{item.subtitle || itemKindLabel(item.kind)}{#if item.folder}<span class="entry-folder">{item.folder}</span>{/if}</small></span>
                {#if item.securityLevel === 'needs-work'}<span class="entry-warning" title="Needs attention" aria-label="Needs attention"></span>{/if}
              </button>
              {#if !multiSelect}<button type="button" class="entry-favourite" class:active={item.favourite} aria-label={item.favourite ? `Remove ${item.title} from favourites` : `Add ${item.title} to favourites`} aria-pressed={item.favourite} on:click={() => onToggleFavourite(item.id, !item.favourite)}><Icon name={item.favourite ? 'star-filled' : 'star'} size={16} /></button>{/if}
            </div>
          {/each}
        </div>
      {:else}
        <div class="empty-vault"><Icon name="search" size={24} /><h3>No matching items.</h3><p>Try another search, category, or collection.</p><button class="secondary-button" on:click={clearEmptyStateFilters}>Show everything</button></div>
      {/if}
    </section>

    <PanelResizer
      label="Resize the item list"
      value={panelWidths.list}
      min={PANEL_WIDTH_LIMITS.list.min}
      max={PANEL_WIDTH_LIMITS.list.max}
      fallback={PANEL_WIDTH_LIMITS.list.fallback}
      onResize={(next) => (panelWidths = { ...panelWidths, list: next })}
      onCommit={commitPanelWidths}
    />

    <section class="login-card-area">
      <button type="button" class="vault-back-button" on:click={() => (pane = 'list')}><Icon name="chevron-left" size={15} /> Back to items</button>
      {#if recentItems.length}
        <nav class="recent-strip" aria-label="Recently viewed items">
          <span class="recent-strip-label">Recent</span>
          {#each recentItems as item (item.id)}
            <button type="button" class="recent-chip" on:click={() => selectRecent(item)} title={item.title}>
              {item.title}
            </button>
          {/each}
        </nav>
      {/if}

      {#if $selection.activeItemKind && $selection.activeItemKind !== 'login'}
        {#if itemDetail}
          <ItemDetail
            kind={$selection.activeItemKind}
            detail={itemDetail}
            {folders}
            onCopy={onItemCopy}
            onToggleFavourite={(favourite) => $selection.activeItemId && onToggleFavourite($selection.activeItemId, favourite)}
            onEdit={onOpenItemEditor}
            onDelete={onDeleteItem}
            onMove={onMoveItem}
            onShowTag={(tag) => onShowCollection(tagFilter(tag))}
          />
        {:else}
          <div class="select-entry" aria-busy={itemLoading}><img class="empty-brand size-lg" src="/favicon.svg" alt="" width="512" height="512" /><h2>{itemLoading ? 'Opening…' : 'Select an item.'}</h2><p>Its details will appear here.</p></div>
        {/if}
      {:else if $vault.loginCard}
        {@const loginCard = $vault.loginCard}
        <div class="login-title-row">
          <div class="entry-avatar large-entry"><WebsiteIcon site={loginCard.site} initials={loginCard.initials} enabled={siteIconsEnabled} /></div>
          <div><h2>{loginCard.title}</h2><div class="login-meta">{#if loginCard.url}<a href={loginCard.url} target="_blank" rel="noreferrer noopener">{loginCard.site}</a>{:else}<span class="site-missing">Website not saved</span>{/if}{#if loginCard.folderId}<span class="login-meta-sep" aria-hidden="true">·</span><button type="button" class="login-folder" on:click={() => onShowCollection(loginCard.folderId ?? '')}><Icon name="folder" size={12} />{loginCard.folder}</button>{/if}{#if selectedEntry?.issueKinds.length}{#each issueChips(selectedEntry.issueKinds).shown as issue (issue)}<span class="issue-chip"><Icon name="alert" size={11} />{issueChipLabel(issue)}</span>{/each}{#if issueChips(selectedEntry.issueKinds).extra}<span class="issue-chip issue-chip-more">+{issueChips(selectedEntry.issueKinds).extra} more</span>{/if}{/if}</div></div>
          <div class="login-title-actions">
            <button type="button" class="card-favourite" class:active={loginCard.favourite} aria-label={loginCard.favourite ? 'Remove from favourites' : 'Add to favourites'} aria-pressed={loginCard.favourite} on:click={() => onToggleFavourite(loginCard.id, !loginCard.favourite)}><Icon name={loginCard.favourite ? 'star-filled' : 'star'} size={17} /></button>
            <button class="more-button" aria-label="Edit login" on:click={onOpenLoginEditor}><Icon name="more" size={19} /></button>
          </div>
        </div>

        {#if activeIssue && selectedEntry}
          <section class="checkup-fix-panel" aria-labelledby="checkup-fix-title">
            <span class="checkup-fix-icon"><Icon name="shield-alert" size={17} /></span>
            <div class="checkup-fix-copy"><strong id="checkup-fix-title">{issueKindLabels[activeIssue].title}</strong>
              {#if activePasswordIssues.length}
                {#each activePasswordIssues as issue (issue.kind)}<p>{issue.explanation}</p>{/each}
                <span class="password-score">Password score: {selectedEntry.passwordScore}/100</span>
              {:else if activeIssue === 'duplicate'}<p>Compare matching records and keep the values you trust.</p>
              {:else if activeIssue === 'url'}<p>Add the sign-in page so Sesame can open and match this login.</p>
              {:else if activeIssue === 'totp'}<p>Add the site's authenticator secret if it supports app-based 2FA.</p>
              {:else if activeIssue === 'recovery'}<p>Save the recovery options this site offers, or mark that it has none.</p>{/if}
            </div>
            {#if activeIssue === 'duplicate'}<button type="button" class="secondary-button" on:click={onOpenDuplicateReview}>Review matches</button>
            {:else if activeIssue === 'url'}<button type="button" class="secondary-button" on:click={onAddWebsite}>Add website</button>
            {:else if activeIssue === 'recovery'}<div class="checkup-fix-actions"><button type="button" class="secondary-button" on:click={onOpenLoginEditor}>Add details</button><button type="button" class="text-button" disabled={recoveryActionWorking} on:click={onOpenRecoveryNotApplicable}>No options</button></div>
            {:else if activePasswordIssues.length}<div class="checkup-fix-actions"><button type="button" class="secondary-button" on:click={onFixWeakPassword}>Generate a new password</button><button type="button" class="text-button" on:click={onOpenLoginEditor}>Edit manually</button></div>
            {:else}<button type="button" class="secondary-button" on:click={onOpenLoginEditor}>Add 2FA</button>{/if}
          </section>
        {/if}

        <section class="credentials-panel" aria-label="Login details">
          <div class="credential-row"><div class="credential-label"><Icon name="user" size={16} /><span>Username</span></div><code>{loginCard.username || 'No username saved'}</code><button type="button" class="credential-button" aria-label="Copy username" disabled={!loginCard.username} on:click={() => onCopy(loginCard.username, 'Username')}><Icon name="copy" size={15} /></button></div>
          {#if loginCard.email}<div class="credential-row"><div class="credential-label"><Icon name="mail" size={16} /><span>Email</span></div><code>{loginCard.email}</code><button type="button" class="credential-button" aria-label="Copy email" on:click={() => onCopy(loginCard.email, 'Email')}><Icon name="copy" size={15} /></button></div>{/if}
          <div class="credential-row"><div class="credential-label"><Icon name="key" size={16} /><span>Password</span></div><code class:concealed={!passwordVisible}>{passwordVisible ? loginCard.password : '••••••••••••••••'}</code><button type="button" class="credential-button" aria-label={passwordVisible ? 'Hide password' : 'Show password'} aria-pressed={passwordVisible} disabled={!loginCard.password} on:click={() => setPasswordVisible(!passwordVisible)}><Icon name={passwordVisible ? 'eye-off' : 'eye'} size={16} /></button><button type="button" class="credential-button" aria-label="Copy password" disabled={!loginCard.password} on:click={() => onCopy(loginCard.password, 'Password')}><Icon name="copy" size={15} /></button><button type="button" class="credential-button" aria-label="Check this password for known breaches" title="Check for breaches" aria-expanded={breachCheckOpen} disabled={!loginCard.password} on:click={onToggleBreachCheck}><Icon name="shield-alert" size={15} /></button></div>
        </section>

        {#if breachCheckOpen}
          <section class="inset-panel breach-check" aria-label="Check for breaches">
            {#if breachCheckResult}
              <p class:breach-found={breachCheckResult.breached}>{breachCheckResult.breached ? `Found in ${breachCheckResult.count.toLocaleString()} known breaches. Replace this password.` : 'Not found in known breaches.'}</p>
              <div class="diagnostic-actions"><button type="button" class="secondary-button settings-manage" on:click={onRunBreachCheck}>Check again</button><button type="button" class="text-button" on:click={onToggleBreachCheck}>Close</button></div>
            {:else}
              <div><strong>Sends a partial hash, never the password</strong><p>{breachCheckError || "Checks a 5-character prefix of this password's SHA-1 hash against Have I Been Pwned. The full password and full hash never leave this device."}</p></div>
              <div class="diagnostic-actions"><button type="button" class="secondary-button settings-manage" disabled={breachCheckWorking} on:click={onRunBreachCheck}>{breachCheckWorking ? 'Checking…' : breachCheckError ? 'Retry' : 'Check for breaches'}</button><button type="button" class="text-button" on:click={onToggleBreachCheck}>Cancel</button></div>
            {/if}
          </section>
        {/if}

        {#if loginCard.tags?.length}
          <section class="details-section">
            <div class="section-heading"><h3>Tags</h3></div>
            <div class="issue-chips">{#each loginCard.tags as tag (tag)}<button type="button" class="tag-chip" on:click={() => onShowCollection(tagFilter(tag))}>{tag}</button>{/each}</div>
          </section>
        {/if}

        <div class="login-actions">
          {#if loginCard.url}<button class="site-action" on:click={() => onOpenWebsite(loginCard.url)}><Icon name="globe" size={17} /><span>Open site</span></button>{:else}<button class="site-action missing-action" on:click={onAddWebsite}><Icon name="globe" size={17} /><span>Add website</span></button>{/if}
          {#if $platformCapabilities.autoType}
            {#if autoTypeEntryId === loginCard.id && autoTypeCountdown > 0}
              <button class="site-action autotype-armed" on:click={onCancelAutoType}><Icon name="keyboard" size={17} /><span>Switch windows… typing in {autoTypeCountdown}. Cancel</span></button>
            {:else}
              <button class="site-action" disabled={!loginCard.username && !loginCard.password} on:click={onStartAutoType}><Icon name="keyboard" size={17} /><span>Auto-type</span></button>
            {/if}
          {/if}
          {#if loginCard.totpCode}<button class="totp-action" on:click={() => loginCard.totpCode && onCopy(loginCard.totpCode, '2FA code')} aria-label={`Copy 2FA code. ${totpRemaining} seconds remaining.`}><span>2FA code</span><strong>{loginCard.totpCode}</strong><span class="totp-countdown" style={`--totp-progress: ${totpProgress}`} aria-hidden="true"><small>{totpRemaining}</small></span></button>{#if totpRefreshIssue}<span class="totp-refresh-issue">Waiting to refresh</span>{/if}{:else}<button class="no-totp" on:click={onOpenLoginEditor}><Icon name="key" size={15} /> Add 2FA</button>{/if}
        </div>

        <section class="details-section">
          <div class="section-heading"><h3>Recovery details</h3><button class="text-button" on:click={onOpenLoginEditor}>Edit</button></div>
          {#if loginCard.recoveryNotApplicable}
            <div class="recovery-empty recovery-exempt"><span class="recovery-icon"><Icon name="shield" size={16} /></span><div><strong>No separate recovery details</strong><p>Marked as not applicable for this login.</p></div><button class="text-button" on:click={onOpenLoginEditor}>Change</button></div>
          {:else if loginCard.backupCodes?.length || loginCard.recoveryEmail || loginCard.recoveryPhone}
            <div class="recovery-grid">{#if loginCard.backupCodes?.length}<article><span class="recovery-icon"><Icon name="file-key" size={15} /></span><div><strong>Backup codes</strong><p>{loginCard.backupCodes.length} stored</p></div><button on:click={() => loginCard.backupCodes && onCopy(loginCard.backupCodes.join('\n'), 'Backup codes')}>Copy</button></article>{/if}{#if loginCard.recoveryEmail}<article><span class="recovery-icon"><Icon name="mail" size={15} /></span><div><strong>Recovery email</strong><p>{loginCard.recoveryEmail}</p></div><span class="status-pill">Saved</span></article>{/if}{#if loginCard.recoveryPhone}<article><span class="recovery-icon"><Icon name="phone" size={15} /></span><div><strong>Recovery phone</strong><p>{loginCard.recoveryPhone}</p></div><span class="status-pill">Saved</span></article>{/if}</div>
          {:else}
            <div class="recovery-empty"><span class="recovery-icon"><Icon name="file-key" size={16} /></span><div><strong>Recovery not reviewed</strong><p>Save an option if this site provides one, or mark that it does not.</p></div><div class="recovery-empty-actions"><button class="text-button" on:click={onOpenLoginEditor}>Add recovery info</button><button class="text-button muted" disabled={recoveryActionWorking} on:click={onOpenRecoveryNotApplicable}>{recoveryActionWorking ? 'Marking…' : 'No recovery options'}</button></div></div>
          {/if}
        </section>
        <section class="details-section">
          <div class="section-heading"><h3>Notes</h3></div>
          <p class="item-notes">{loginCard.notes || 'No notes saved for this account.'}</p>
        </section>
        {#if loginCard.urls && loginCard.urls.length > 1}
          <section class="details-section">
            <div class="section-heading"><h3>Additional websites</h3></div>
            {#each loginCard.urls.slice(1) as url (url)}<p><a href={url} target="_blank" rel="noreferrer noopener">{url}</a></p>{/each}
          </section>
        {/if}
        {#if loginCard.legacyFields?.length}
          <section class="details-section">
            <div class="section-heading"><h3>Legacy data</h3></div>
            {#each loginCard.legacyFields as field, index (index)}<p><strong>{field.label}</strong>: {field.secret ? 'Secret value stored' : field.value} <button class="text-button" on:click={() => onCopy(field.value, field.label)}>Copy</button></p>{/each}
          </section>
        {/if}
      {:else}
        <div class="select-entry"><img class="empty-brand size-lg" src="/favicon.svg" alt="" width="512" height="512" /><h2>Select an item.</h2><p>Its details will appear here.</p></div>
      {/if}
    </section>

  </div>
{/if}

<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import { issueChipLabel, issueChips, issueFilterLabel, issueKindLabels } from '../issue-kinds'
  import { useAppStores } from '../stores/app-stores'
  import type { BreachCheckResult, IssueKind, VaultEntry } from '../types'
  import { FAVOURITES_FILTER, RECENT_FILTER, SORT_MODES, sortModeLabels } from '../vault-collections'
  import PanelResizer from './PanelResizer.svelte'
  import WebsiteIcon from './WebsiteIcon.svelte'
  import { PANEL_WIDTH_LIMITS, readPanelWidths, storePanelWidths } from '../preferences'

  const PASSWORD_REVEAL_TIMEOUT_MS = 30_000

  export let visibleEntries: VaultEntry[] = []
  export let passwordVisible = false
  export let siteIconsEnabled = false
  export let totpRemaining = 0
  export let totpProgress = '0%'
  export let totpRefreshIssue = false
  export let multiSelect = false
  export let selectedIds: string[] = []
  export let bulkFolderId = ''
  export let recoveryActionWorking = false
  export let onSelectEntry: (id: string) => void
  export let onOpenNewLogin: (password?: string) => void
  export let onImport: () => void
  export let onClearSearch: () => void
  export let onSearch: (query: string) => void
  export let onSetSortMode: (mode: string) => void
  export let onClearSecurityFilter: () => void
  export let onShowFolder: (folderId: string | null) => void
  export let onOrganizeFolders: () => void
  export let onOpenContextMenu: (position: { x: number; y: number }, id: string) => void
  export let onOpenLoginEditor: () => void
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
  export let onShowSecurityFilter: (filter: IssueKind) => void
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
  $: selectedEntry = snapshotEntries.find((entry) => entry.id === $selection.activeEntryId) ?? null
  $: selectedSet = new Set(selectedIds)
  $: allVisibleSelected = visibleEntries.length > 0 && visibleEntries.every((entry) => selectedSet.has(entry.id))
  $: allSelectedFavourite = selectedIds.length > 0 && snapshotEntries.filter((entry) => selectedSet.has(entry.id)).every((entry) => entry.favourite)
  $: favouriteCount = snapshotEntries.filter((entry) => entry.favourite).length
  $: recentCount = snapshotEntries.filter((entry) => entry.lastUsedAt).length
  $: unfiledCount = snapshotEntries.filter((entry) => !entry.folderId).length
  $: activeFolder = folders.find((folder) => folder.id === $selection.folderFilter)
  $: folderHeading = $selection.folderFilter === null
    ? 'All logins'
    : $selection.folderFilter === FAVOURITES_FILTER
      ? 'Favourites'
      : $selection.folderFilter === RECENT_FILTER
        ? 'Recently used'
        : $selection.folderFilter === ''
          ? 'Unfiled'
          : activeFolder?.name ?? 'Folder'
  $: activeIssue = $selection.securityFilter
  $: activePasswordIssues = selectedEntry?.passwordIssues.filter((issue) => issue.kind === activeIssue) ?? []

  $: securityGood = $vault.snapshot?.security.good ?? 0
  $: healthPercent = snapshotEntries.length ? Math.round((securityGood / snapshotEntries.length) * 100) : 100
  $: healthTier = healthPercent >= 80 ? 'good' : healthPercent >= 50 ? 'fair' : 'weak'

  let panelWidths = readPanelWidths()
  const commitPanelWidths = () => storePanelWidths(panelWidths)

  $: recentEntries = $selection.recentEntryIds
    .map((id) => snapshotEntries.find((entry) => entry.id === id))
    .filter((entry): entry is VaultEntry => Boolean(entry) && entry!.id !== $selection.activeEntryId)

  let folderStrip: HTMLElement
  let searchInput: HTMLInputElement
  let passwordRevealTimer: ReturnType<typeof setTimeout> | null = null
  let sortMenuOpen = false
  let sortContainer: HTMLElement
  let sortButton: HTMLButtonElement

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

  $: if ($selection.folderFilter === RECENT_FILTER) sortMenuOpen = false
  $: if ($selection.activeEntryId) clearPasswordRevealTimer()
  onDestroy(clearPasswordRevealTimer)

  function folderCount(folderId: string) {
    return snapshotEntries.filter((entry) => entry.folderId === folderId).length
  }

  function keyboardContextMenu(event: KeyboardEvent, id: string) {
    if (event.key !== 'ContextMenu' && !(event.shiftKey && event.key === 'F10')) return
    event.preventDefault()
    const bounds = (event.currentTarget as HTMLElement).getBoundingClientRect()
    onOpenContextMenu({ x: bounds.left + 24, y: bounds.top + 24 }, id)
  }

  function scrollFolders(direction: -1 | 1) {
    folderStrip?.scrollBy({ left: Math.max(120, folderStrip.clientWidth * 0.8) * direction, behavior: 'smooth' })
  }

  function activateRow(entry: VaultEntry) {
    if (multiSelect) onToggleMultiSelect(entry.id, !selectedSet.has(entry.id))
    else onSelectEntry(entry.id)
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    const target = event.target as HTMLElement | null
    if (target?.closest('[role="dialog"]')) return
    const editing = target?.matches('input, textarea, select, [contenteditable="true"]')
    if (!editing && (event.key === '/' || ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k'))) {
      event.preventDefault()
      searchInput?.focus()
      searchInput?.select()
      return
    }
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
    if (!multiSelect || editing) return
    if (event.key === 'Escape') {
      event.preventDefault()
      onCancelMultiSelect()
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
      event.preventDefault()
      onSelectVisible(allVisibleSelected ? [] : visibleEntries.map((entry) => entry.id))
    }
  }

  function clearEmptyStateFilters() {
    onClearSearch()
    onClearSecurityFilter()
    if ($selection.folderFilter !== null) onShowFolder(null)
  }
</script>

<svelte:window on:keydown={handleWindowKeydown} on:mousedown={handleSortOutside} />

{#if !snapshotEntries.length}
  <section class="empty-workspace">
    <img class="empty-brand size-md" src="/favicon.svg" alt="" />
    <p class="eyebrow">Start here</p>
    <h2>Bring in your logins.</h2>
    <p>Import an export from another password manager. Sesame reads it on this device.</p>
    <button class="primary-button" on:click={onImport}>Choose export file</button>
    <button class="text-button empty-add" on:click={() => onOpenNewLogin()}>Add a login instead</button>
  </section>
{:else}
  <div class="vault-layout" style="--vault-list-width: {panelWidths.list}px; --vault-rail-width: {panelWidths.rail}px;">
    <section class="entry-list-panel" aria-label="Saved logins">
      <div class="panel-heading">
        <div>
          <h2>{$selection.securityFilter ? 'Security review' : folderHeading}</h2>
          <p>{visibleEntries.length} {visibleEntries.length === 1 ? 'login' : 'logins'}</p>
        </div>
        <div class="panel-heading-actions">
          <button type="button" class="select-logins-button" class:active={multiSelect} on:click={() => multiSelect ? onCancelMultiSelect() : onStartMultiSelect()}>{multiSelect ? 'Done' : 'Select'}</button>
          <button type="button" class="add-login-button" on:click={() => onOpenNewLogin()} aria-label="Add a login"><Icon name="plus" size={15} strokeWidth={2.2} /><span>Add</span></button>
        </div>
      </div>

      <div class="folder-navigation">
        <button type="button" class="folder-scroll-control" aria-label="Previous collections" title="Previous collections" on:click={() => scrollFolders(-1)}><Icon name="chevron-left" size={15} /></button>
        <nav bind:this={folderStrip} class="folder-strip" aria-label="Vault collections">
          <button type="button" class:active={$selection.folderFilter === null} aria-pressed={$selection.folderFilter === null} on:click={() => onShowFolder(null)}><Icon name="folder" size={14} /><span>All</span><small>{snapshotEntries.length}</small></button>
          <button type="button" class:active={$selection.folderFilter === FAVOURITES_FILTER} aria-pressed={$selection.folderFilter === FAVOURITES_FILTER} on:click={() => onShowFolder(FAVOURITES_FILTER)}><span class="collection-star" aria-hidden="true">★</span><span>Favourites</span><small>{favouriteCount}</small></button>
          <button type="button" class:active={$selection.folderFilter === RECENT_FILTER} aria-pressed={$selection.folderFilter === RECENT_FILTER} on:click={() => onShowFolder(RECENT_FILTER)}><Icon name="refresh" size={14} /><span>Recent</span><small>{recentCount}</small></button>
          {#each folders as folder (folder.id)}
            <button type="button" class:active={$selection.folderFilter === folder.id} aria-pressed={$selection.folderFilter === folder.id} on:click={() => onShowFolder(folder.id)}><Icon name="folder" size={14} /><span>{folder.name}</span><small>{folderCount(folder.id)}</small></button>
          {/each}
          <button type="button" class:active={$selection.folderFilter === ''} aria-pressed={$selection.folderFilter === ''} on:click={() => onShowFolder('')}><Icon name="folder" size={14} /><span>Unfiled</span><small>{unfiledCount}</small></button>
        </nav>
        <button type="button" class="folder-scroll-control" aria-label="Next collections" title="Next collections" on:click={() => scrollFolders(1)}><Icon name="chevron-right" size={15} /></button>
        <button type="button" class="organize-folders" aria-label="Organize folders" title="Organize folders" on:click={onOrganizeFolders}><Icon name="settings" size={14} /></button>
      </div>

      {#if activeIssue}<button class="active-filter" on:click={onClearSecurityFilter}>Showing {issueFilterLabel(activeIssue)} <span aria-hidden="true">×</span></button>{/if}

      <div class="vault-list-tools">
        <label class="search-box"><Icon name="search" size={15} /><input bind:this={searchInput} value={$selection.searchQuery} on:input={(event) => onSearch(event.currentTarget.value)} placeholder="Search" aria-label="Search logins" aria-keyshortcuts="Control+K Meta+K /" />{#if !$selection.searchQuery}<kbd aria-hidden="true">/</kbd>{:else}<button type="button" aria-label="Clear search" on:click={onClearSearch}>×</button>{/if}</label>
        <div class="sort-control" bind:this={sortContainer}>
          <span id="sort-control-label" class="sr-only">Sort logins</span>
          <button
            bind:this={sortButton}
            type="button"
            class="sort-select-trigger"
            aria-haspopup="listbox"
            aria-labelledby="sort-control-label"
            aria-controls="sort-control-options"
            aria-expanded={sortMenuOpen}
            disabled={$selection.folderFilter === RECENT_FILTER}
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
        <button type="button" class="import-button" on:click={onImport}><Icon name="archive" size={14} /><span>Import</span></button>
      </div>

      {#if multiSelect}
        <div class="bulk-toolbar" role="region" aria-label="Bulk login actions">
          <label class="bulk-select-all"><input type="checkbox" checked={allVisibleSelected} aria-label="Select all visible logins" on:change={() => onSelectVisible(allVisibleSelected ? [] : visibleEntries.map((entry) => entry.id))} /><span>{selectedIds.length} selected</span></label>
          <select value={bulkFolderId} aria-label="Destination folder" on:change={(event) => onSetBulkFolderId(event.currentTarget.value)}>
            <option value="">Unfiled</option>
            {#each folders as folder (folder.id)}<option value={folder.id}>{folder.name}</option>{/each}
          </select>
          <button type="button" class="secondary-button bulk-move-button" disabled={!selectedIds.length} on:click={onBulkMove}>Move</button>
          <button type="button" class="secondary-button" disabled={!selectedIds.length} on:click={onBulkFavourite}>{allSelectedFavourite ? 'Unfavourite' : 'Favourite'}</button>
          <button type="button" class="editor-delete" disabled={!selectedIds.length} on:click={onBulkDelete}>Delete</button>
        </div>
      {/if}

      {#if visibleEntries.length}
        <div class="entry-list" role="list" aria-label={multiSelect ? 'Select logins' : 'Logins'}>
          {#each visibleEntries as entry (entry.id)}
            <div class="entry-row" class:selected={$selection.activeEntryId === entry.id && !multiSelect} class:multi-selected={selectedSet.has(entry.id)} role="listitem" on:contextmenu|preventDefault={(event) => !multiSelect && onOpenContextMenu({ x: event.clientX, y: event.clientY }, entry.id)}>
              {#if multiSelect}<input class="entry-select-box" type="checkbox" checked={selectedSet.has(entry.id)} aria-label={`Select ${entry.title}`} on:change={(event) => onToggleMultiSelect(entry.id, event.currentTarget.checked)} />{/if}
              <button type="button" class="entry-row-main" aria-current={!multiSelect && $selection.activeEntryId === entry.id ? 'true' : undefined} aria-pressed={multiSelect ? selectedSet.has(entry.id) : undefined} on:click={() => activateRow(entry)} on:keydown={(event) => !multiSelect && keyboardContextMenu(event, entry.id)}>
                <span class="entry-avatar"><WebsiteIcon site={entry.site} initials={entry.initials} enabled={siteIconsEnabled} /></span>
                <span class="entry-title"><strong>{entry.title}</strong><small>{entry.site}{#if entry.folder}<span class="entry-folder">{entry.folder}</span>{/if}</small></span>
                {#if entry.securityLevel !== 'good'}<span class="entry-warning" title="Needs attention" aria-label="Needs attention"></span>{/if}
              </button>
              {#if !multiSelect}<button type="button" class="entry-favourite" class:active={entry.favourite} aria-label={entry.favourite ? `Remove ${entry.title} from favourites` : `Add ${entry.title} to favourites`} aria-pressed={entry.favourite} on:click={() => onToggleFavourite(entry.id, !entry.favourite)}>{entry.favourite ? '★' : '☆'}</button>{/if}
            </div>
          {/each}
        </div>
      {:else}
        <div class="empty-vault"><Icon name="search" size={24} /><h3>No matching logins.</h3><p>Try another search or collection.</p><button class="secondary-button" on:click={clearEmptyStateFilters}>Show all logins</button></div>
      {/if}
    </section>

    <PanelResizer
      label="Resize the login list"
      value={panelWidths.list}
      min={PANEL_WIDTH_LIMITS.list.min}
      max={PANEL_WIDTH_LIMITS.list.max}
      fallback={PANEL_WIDTH_LIMITS.list.fallback}
      onResize={(next) => (panelWidths = { ...panelWidths, list: next })}
      onCommit={commitPanelWidths}
    />

    <section class="login-card-area">
      {#if recentEntries.length}
        <nav class="recent-strip" aria-label="Recently viewed logins">
          <span class="recent-strip-label">Recent</span>
          {#each recentEntries as entry (entry.id)}
            <button type="button" class="recent-chip" on:click={() => onSelectEntry(entry.id)} title={entry.title}>
              {entry.title}
            </button>
          {/each}
        </nav>
      {/if}

      {#if $vault.loginCard}
        {@const loginCard = $vault.loginCard}
        <div class="login-title-row">
          <div class="entry-avatar large-entry"><WebsiteIcon site={loginCard.site} initials={loginCard.initials} enabled={siteIconsEnabled} /></div>
          <div><p class="eyebrow">Login</p><h2>{loginCard.title}</h2><div class="login-meta">{#if loginCard.url}<a href={loginCard.url} target="_blank" rel="noreferrer noopener">{loginCard.site}</a>{:else}<span class="site-missing">Website not saved</span>{/if}{#if loginCard.folderId}<button type="button" class="folder-badge" on:click={() => onShowFolder(loginCard.folderId ?? '')}><Icon name="folder" size={12} />{loginCard.folder}</button>{/if}</div>{#if selectedEntry?.issueKinds.length}<div class="issue-chips">{#each issueChips(selectedEntry.issueKinds).shown as issue (issue)}<span class="issue-chip"><Icon name="alert" size={11} />{issueChipLabel(issue)}</span>{/each}{#if issueChips(selectedEntry.issueKinds).extra}<span class="issue-chip issue-chip-more">+{issueChips(selectedEntry.issueKinds).extra} more</span>{/if}</div>{/if}</div>
          <div class="login-title-actions">
            <button type="button" class="card-favourite" class:active={loginCard.favourite} aria-label={loginCard.favourite ? 'Remove from favourites' : 'Add to favourites'} aria-pressed={loginCard.favourite} on:click={() => onToggleFavourite(loginCard.id, !loginCard.favourite)}>{loginCard.favourite ? '★' : '☆'}</button>
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
          <section class="support-review breach-check" aria-label="Check for breaches">
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
          <section class="notes-section"><p class="eyebrow">Tags</p><p>{loginCard.tags.join(', ')}</p></section>
        {/if}

        <div class="login-actions">
          {#if loginCard.url}<button class="site-action" on:click={() => onOpenWebsite(loginCard.url)}><Icon name="globe" size={17} /><span>Open site</span></button>{:else}<button class="site-action missing-action" on:click={onAddWebsite}><Icon name="globe" size={17} /><span>Add website</span></button>{/if}
          {#if autoTypeEntryId === loginCard.id && autoTypeCountdown > 0}
            <button class="site-action autotype-armed" on:click={onCancelAutoType}><Icon name="keyboard" size={17} /><span>Switch windows… typing in {autoTypeCountdown}. Cancel</span></button>
          {:else}
            <button class="site-action" disabled={!loginCard.username && !loginCard.password} on:click={onStartAutoType}><Icon name="keyboard" size={17} /><span>Auto-type</span></button>
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
        <section class="notes-section"><p class="eyebrow">Notes</p><p>{loginCard.notes || 'No notes saved for this account.'}</p></section>
        {#if loginCard.urls && loginCard.urls.length > 1}
          <section class="notes-section"><p class="eyebrow">Additional websites</p>{#each loginCard.urls.slice(1) as url (url)}<p><a href={url} target="_blank" rel="noreferrer noopener">{url}</a></p>{/each}</section>
        {/if}
        {#if loginCard.legacyFields?.length}
          <section class="notes-section"><p class="eyebrow">Legacy data</p>{#each loginCard.legacyFields as field, index (index)}<p><strong>{field.label}</strong>: {field.secret ? 'Secret value stored' : field.value} <button class="text-button" on:click={() => onCopy(field.value, field.label)}>Copy</button></p>{/each}</section>
        {/if}
      {:else}
        <div class="select-entry"><img class="empty-brand size-lg" src="/favicon.svg" alt="" /><h2>Select a login.</h2><p>Its sign-in details will appear here.</p></div>
      {/if}
    </section>

    <PanelResizer
      label="Resize the security panel"
      value={panelWidths.rail}
      min={PANEL_WIDTH_LIMITS.rail.min}
      max={PANEL_WIDTH_LIMITS.rail.max}
      fallback={PANEL_WIDTH_LIMITS.rail.fallback}
      direction={-1}
      onResize={(next) => (panelWidths = { ...panelWidths, rail: next })}
      onCommit={commitPanelWidths}
    />

    <aside class="security-rail">
      <p class="eyebrow">Security status</p>
      <div class="score-ring" data-tier={healthTier} style={`--p: ${Math.max(healthPercent, 4)}%`} role="img" aria-label={`Vault health ${healthPercent} percent. ${securityGood} of ${snapshotEntries.length} accounts ready.`}><div class="score-ring-inner"><strong>{healthPercent}<span class="score-unit">%</span></strong></div></div>
      <h3>{($vault.snapshot?.security.needsAttention ?? 0) > 0 ? 'Review needed.' : 'All clear.'}</h3>
      <p>{($vault.snapshot?.security.needsAttention ?? 0) > 0 ? `${securityGood} of ${snapshotEntries.length} accounts are ready. Choose a check to work through the rest.` : 'Every saved account is in good shape.'}</p>
      {#if ($vault.snapshot?.security.needsAttention ?? 0) > 0}
        <div class="rail-breakdown">
          {#if $vault.snapshot?.security.weakPasswords}<button type="button" on:click={() => onShowSecurityFilter('weak-password')}><span class="rail-dot"></span>Weak passwords<strong>{$vault.snapshot.security.weakPasswords}</strong></button>{/if}
          {#if $vault.snapshot?.security.commonPasswords}<button type="button" on:click={() => onShowSecurityFilter('common-password')}><span class="rail-dot"></span>Common passwords<strong>{$vault.snapshot.security.commonPasswords}</strong></button>{/if}
          {#if $vault.snapshot?.security.reusedPasswords}<button type="button" on:click={() => onShowSecurityFilter('reused-password')}><span class="rail-dot"></span>Reused passwords<strong>{$vault.snapshot.security.reusedPasswords}</strong></button>{/if}
          {#if $vault.snapshot?.security.compromisedPatterns}<button type="button" on:click={() => onShowSecurityFilter('compromised-pattern')}><span class="rail-dot"></span>Unsafe patterns<strong>{$vault.snapshot.security.compromisedPatterns}</strong></button>{/if}
          {#if $vault.snapshot?.security.oldPasswords}<button type="button" on:click={() => onShowSecurityFilter('old-password')}><span class="rail-dot"></span>Old passwords<strong>{$vault.snapshot.security.oldPasswords}</strong></button>{/if}
          {#if $vault.snapshot?.security.noTotp}<button type="button" on:click={() => onShowSecurityFilter('totp')}><span class="rail-dot"></span>No 2FA saved<strong>{$vault.snapshot.security.noTotp}</strong></button>{/if}
          {#if $vault.snapshot?.security.missingUrls}<button type="button" on:click={() => onShowSecurityFilter('url')}><span class="rail-dot"></span>No website<strong>{$vault.snapshot.security.missingUrls}</strong></button>{/if}
          {#if $vault.snapshot?.security.missingRecovery}<button type="button" on:click={() => onShowSecurityFilter('recovery')}><span class="rail-dot"></span>Recovery not reviewed<strong>{$vault.snapshot.security.missingRecovery}</strong></button>{/if}
          {#if $vault.snapshot?.security.duplicateCandidates}<button type="button" on:click={() => onShowSecurityFilter('duplicate')}><span class="rail-dot"></span>Possible duplicates<strong>{$vault.snapshot.security.duplicateCandidates}</strong></button>{/if}
        </div>
      {/if}
      <button class="secondary-button rail-button" on:click={onGoSecurity}>See full checkup</button>
    </aside>
  </div>
{/if}

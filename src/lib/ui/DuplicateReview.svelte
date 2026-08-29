<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { CleanupEntry, DuplicateGroup } from '../types'

  export let groups: DuplicateGroup[] = []
  export let selectedGroupId: string | undefined = undefined
  export let selectedEntryIds: string[] = []
  export let onSelectGroup: (groupId: string) => void = () => undefined
  export let onSelectEntry: (entryId: string, selected: boolean) => void = () => undefined
  export let onEdit: (entry: CleanupEntry) => void = () => undefined
  export let onMerge: (group: DuplicateGroup, entries: CleanupEntry[]) => void = () => undefined
  export let onDelete: (entry: CleanupEntry) => void = () => undefined

  $: activeGroup = groups.find((group) => group.id === selectedGroupId) ?? groups[0]
  $: selectedEntries = activeGroup?.entries.filter((entry) => selectedEntryIds.includes(entry.id)) ?? []

  function displayInitials(entry: CleanupEntry) {
    if (entry.initials?.trim()) return entry.initials.slice(0, 2)
    return entry.title.trim().slice(0, 1).toUpperCase() || '?'
  }

  function groupTitle(group: DuplicateGroup) {
    return group.label?.trim() || group.site?.trim() || group.entries[0]?.title || 'Duplicate logins'
  }
</script>

<section class="cleanup-review" aria-label="Duplicate login review">
  <aside class="group-panel" aria-label="Duplicate groups">
    <header class="panel-header">
      <div>
        <h2>Possible duplicates</h2>
        <p>{groups.length} {groups.length === 1 ? 'group' : 'groups'} to review</p>
      </div>
    </header>

    {#if groups.length}
      <div class="group-list">
        {#each groups as group (group.id)}
          <button
            type="button"
            class:active={activeGroup?.id === group.id}
            aria-current={activeGroup?.id === group.id ? 'true' : undefined}
            on:click={() => onSelectGroup(group.id)}
          >
            <span class="group-icon" aria-hidden="true"><Icon name="copy" size={15} /></span>
            <span class="group-copy">
              <strong>{groupTitle(group)}</strong>
              <small>{group.entries.length} matching {group.entries.length === 1 ? 'login' : 'logins'}</small>
            </span>
            <Icon name="chevron-right" size={15} />
          </button>
        {/each}
      </div>
    {:else}
      <div class="empty-state">
        <span aria-hidden="true"><Icon name="check" size={18} /></span>
        <strong>No duplicates found</strong>
        <p>Your saved logins do not have any obvious matches.</p>
      </div>
    {/if}
  </aside>

  <div class="review-panel">
    {#if activeGroup}
      <header class="review-header">
        <div>
          <p class="context-label">Reviewing</p>
          <h2>{groupTitle(activeGroup)}</h2>
          <p>Choose the entries that belong together. You can inspect or remove one before merging.</p>
        </div>
        <span class="selection-count">{selectedEntries.length} selected</span>
      </header>

      <div class="review-entry-list" aria-label="Matching login entries">
        {#each activeGroup.entries as entry (entry.id)}
          {@const isSelected = selectedEntryIds.includes(entry.id)}
          <article class:selected={isSelected}>
            <button
              type="button"
              class="entry-select"
              aria-pressed={isSelected}
              aria-label={`${isSelected ? 'Deselect' : 'Select'} ${entry.title}`}
              on:click={() => onSelectEntry(entry.id, !isSelected)}
            >
              <span class="selection-box" aria-hidden="true">
                {#if isSelected}<Icon name="check" size={12} strokeWidth={2.3} />{/if}
              </span>
              <span class="entry-avatar" aria-hidden="true">{displayInitials(entry)}</span>
              <span class="entry-copy">
                <strong>{entry.title}</strong>
                <small>{entry.username || 'No username'}{entry.site ? ` · ${entry.site}` : ''}</small>
                {#if entry.reason}<span>{entry.reason}</span>{/if}
              </span>
            </button>
            <div class="entry-actions">
              <button type="button" on:click={() => onEdit(entry)}>Edit</button>
              <button type="button" class="delete-action" on:click={() => onDelete(entry)}>Delete</button>
            </div>
          </article>
        {/each}
      </div>

      <footer class="review-footer">
        <p>{selectedEntries.length < 2 ? 'Select at least two entries to merge.' : 'The selected entries will be combined after you confirm.'}</p>
        <button
          type="button"
          class="merge-button"
          disabled={selectedEntries.length < 2}
          on:click={() => onMerge(activeGroup, selectedEntries)}
        >
          <Icon name="copy" size={15} />
          Merge {selectedEntries.length || ''}
        </button>
      </footer>
    {:else}
      <div class="review-empty">
        <Icon name="shield" size={24} />
        <h2>Nothing to review</h2>
        <p>Duplicate groups will appear here when Sesame finds them.</p>
      </div>
    {/if}
  </div>
</section>

<style>
  .cleanup-review {
    display: grid;
    min-height: 0;
    height: 100%;
    grid-template-columns: 272px minmax(0, 1fr);
    gap: var(--space-3);
    color: var(--text);
  }

  .group-panel,
  .review-panel {
    min-height: 0;
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-raised);
    overflow: hidden;
  }

  .group-panel,
  .review-panel {
    display: flex;
    flex-direction: column;
  }

  .panel-header,
  .review-header {
    flex: none;
    border-bottom: 1px solid var(--border-soft);
  }

  .panel-header { padding: var(--space-4); }

  h2,
  p { margin: 0; }

  .panel-header h2,
  .review-header h2,
  .review-empty h2 {
    color: var(--text-heading);
    font-family: var(--font-display);
    font-size: var(--type-4);
    font-weight: 500;
    letter-spacing: -.02em;
    line-height: 1.25;
  }

  .panel-header p,
  .review-header > div > p:last-child,
  .review-empty p,
  .empty-state p {
    margin-top: var(--space-1);
    color: var(--text-muted);
    font-size: var(--type-1);
    line-height: 1.45;
  }

  .group-list {
    min-height: 0;
    padding: var(--space-2);
    overflow-y: auto;
    scrollbar-gutter: stable;
  }

  .group-list button {
    display: grid;
    width: 100%;
    grid-template-columns: auto minmax(0, 1fr) auto;
    align-items: center;
    gap: var(--space-3);
    border: 0;
    border-radius: var(--radius-sm);
    padding: var(--space-3);
    color: var(--text-muted);
    background: transparent;
    text-align: left;
  }

  .group-list button:hover { background: var(--tint-hover); }
  .group-list button.active { color: var(--accent-link); background: var(--tint); }

  .group-icon {
    display: grid;
    width: 32px;
    height: 32px;
    place-items: center;
    border-radius: var(--radius-sm);
    color: var(--chip-icon);
    background: var(--chip-bg);
  }

  .group-copy,
  .entry-copy { display: grid; min-width: 0; gap: 2px; }
  .group-copy strong,
  .entry-copy strong { overflow: hidden; color: var(--text); font-size: var(--type-2); font-weight: 700; text-overflow: ellipsis; white-space: nowrap; }
  .group-copy small,
  .entry-copy small { overflow: hidden; color: var(--text-muted); font-size: var(--type-1); text-overflow: ellipsis; white-space: nowrap; }

  .review-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-5);
    padding: var(--space-5);
  }

  .review-header > div { min-width: 0; }
  .review-header > div > p:last-child { max-width: 540px; margin-top: var(--space-2); font-size: var(--type-2); }
  .context-label { margin-bottom: var(--space-1); color: var(--text-muted); font-size: var(--type-1); font-weight: 700; }

  .selection-count {
    flex: none;
    border-radius: var(--radius-pill);
    padding: 6px 10px;
    color: var(--accent-link);
    background: var(--tint);
    font-size: var(--type-1);
    font-weight: 700;
  }

  .review-entry-list {
    min-height: 0;
    flex: 1;
    padding: var(--space-3) var(--space-5);
    overflow-y: auto;
    scrollbar-gutter: stable;
  }

  .review-entry-list article {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: var(--space-3);
    border-bottom: 1px solid var(--border-soft);
    background: transparent;
  }

  .review-entry-list article.selected { background: var(--surface-inset); }

  .entry-select {
    display: grid;
    min-width: 0;
    grid-template-columns: auto auto minmax(0, 1fr);
    align-items: center;
    gap: var(--space-3);
    border: 0;
    padding: var(--space-3);
    color: var(--text);
    background: transparent;
    text-align: left;
  }

  .entry-select:hover .entry-copy strong { color: var(--accent-link); }

  .selection-box {
    display: grid;
    width: 18px;
    height: 18px;
    place-items: center;
    border: 1px solid var(--border-input);
    border-radius: 5px;
    color: var(--on-accent);
    background: var(--surface);
  }

  .entry-select[aria-pressed='true'] .selection-box { border-color: var(--accent); background: var(--accent); }

  .entry-avatar {
    display: grid;
    width: 36px;
    height: 36px;
    place-items: center;
    border-radius: var(--radius-sm);
    color: var(--accent-link);
    background: var(--chip-bg);
    font-size: var(--type-2);
    font-weight: 750;
  }

  .entry-copy span { color: var(--warn-text); font-size: var(--type-1); }

  .entry-actions { display: flex; align-items: center; gap: var(--space-1); padding-right: var(--space-3); }
  .entry-actions button {
    min-height: 32px;
    border: 0;
    border-radius: var(--radius-sm);
    padding: 0 var(--space-2);
    color: var(--accent-link);
    background: transparent;
    font-size: var(--type-1);
    font-weight: 700;
  }
  .entry-actions button:hover { background: var(--tint); }
  .entry-actions .delete-action { color: var(--danger); }
  .entry-actions .delete-action:hover { background: var(--danger-tint); }

  .review-footer {
    display: flex;
    flex: none;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    border-top: 1px solid var(--border);
    padding: var(--space-4) var(--space-5);
    background: var(--surface-2);
  }

  .review-footer p { color: var(--text-muted); font-size: var(--type-1); }
  .merge-button {
    display: inline-flex;
    min-height: 38px;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    border: 0;
    border-radius: var(--radius-sm);
    padding: 0 var(--space-4);
    color: var(--on-accent);
    background: var(--accent);
    font-size: var(--type-2);
    font-weight: 700;
  }
  .merge-button:hover:not(:disabled) { background: var(--accent-hover); }
  .merge-button:disabled { cursor: not-allowed; opacity: .5; }

  .empty-state,
  .review-empty {
    display: grid;
    min-height: 0;
    flex: 1;
    place-content: center;
    justify-items: center;
    padding: var(--space-6);
    color: var(--ok-text);
    text-align: center;
  }

  .empty-state > span {
    display: grid;
    width: 38px;
    height: 38px;
    place-items: center;
    margin-bottom: var(--space-3);
    border-radius: 50%;
    background: var(--ok-bg);
  }
  .empty-state strong { color: var(--text); font-size: var(--type-2); }
  .review-empty { color: var(--chip-icon); }
  .review-empty h2 { margin-top: var(--space-3); }

  button:focus-visible {
    outline: 3px solid var(--focus-ring);
    outline-offset: -2px;
  }

  @media (max-width: 760px) {
    .cleanup-review { height: auto; grid-template-columns: 1fr; }
    .group-panel { max-height: 280px; }
    .review-panel { min-height: 480px; }
    .review-header,
    .review-footer { align-items: flex-start; flex-direction: column; }
    .review-footer .merge-button { width: 100%; }
  }
</style>

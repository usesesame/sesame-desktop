<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import type { SyncConflictSide } from '../types'

  export let open = false
  export let thisDevice: SyncConflictSide
  export let otherDevice: SyncConflictSide
  export let working = false
  export let error = ''
  /// Disabled until both sides were read for real: the numbers would be placeholders.
  export let detailsLoaded = false
  export let detailsError = ''
  export let onCancel: () => void
  export let onKeep: (choice: 'this' | 'other') => void

  // No default: either choice discards the other device's changes.
  let choice: 'this' | 'other' | '' = ''

  $: if (!open) choice = ''

  function formatWhen(value: string): string {
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  }
</script>

{#if open}
  <ModalShell {open} onClose={onCancel} labelledby="sync-conflict-title" describedby="sync-conflict-body" ariaBusy={working}>
    <h2 id="sync-conflict-title">Two devices changed this vault</h2>
    <div id="sync-conflict-body">
      <p class="modal-lede">
        Another device saved changes while this one was offline. Sesame does not merge vaults,
        because merging passwords can silently drop a change. Choose which version to keep.
      </p>

      <div class="sync-conflict-grid" role="radiogroup" aria-label="Version to keep">
        <label class="sync-conflict-side" class:selected={choice === 'this'}>
          <input type="radio" name="sync-conflict" value="this" bind:group={choice} disabled={working} />
          <span class="sync-conflict-head">This device</span>
          <span class="sync-conflict-meta">Revision {thisDevice.revision}</span>
          {#if thisDevice.changedAt}<span class="sync-conflict-meta">Changed {formatWhen(thisDevice.changedAt)}</span>{/if}
          <span class="sync-conflict-count">{thisDevice.entryCount} logins</span>
        </label>

        <label class="sync-conflict-side" class:selected={choice === 'other'}>
          <input type="radio" name="sync-conflict" value="other" bind:group={choice} disabled={working} />
          <span class="sync-conflict-head">{otherDevice.deviceLabel || 'Other device'}</span>
          <span class="sync-conflict-meta">Revision {otherDevice.revision}</span>
          {#if otherDevice.changedAt}<span class="sync-conflict-meta">Uploaded {formatWhen(otherDevice.changedAt)}</span>{/if}
          <span class="sync-conflict-count">{otherDevice.entryCount} logins</span>
        </label>
      </div>

      <p class="sync-warning">
        The version you do not keep stops being your vault. Sesame saves an encrypted copy of
        both versions on this device first, so you can go back to either one.
      </p>

      {#if detailsError}<p class="form-error" role="alert">{detailsError}</p>{/if}
      {#if error}<p class="form-error" role="alert">{error}</p>{/if}
    </div>

    <div class="modal-actions">
      <button type="button" class="secondary-button" on:click={onCancel} disabled={working}>Decide later</button>
      <button
        type="button"
        class="primary-button"
        on:click={() => choice && onKeep(choice)}
        disabled={!choice || working || !detailsLoaded}
      >
        {working ? 'Saving…' : 'Keep selected version'}
      </button>
    </div>
  </ModalShell>
{/if}

<style>
  .sync-conflict-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-3);
    margin: var(--space-4) 0;
  }
  .sync-conflict-side {
    display: grid;
    gap: var(--space-1);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    background: var(--surface-inset);
    cursor: pointer;
  }
  .sync-conflict-side.selected {
    border-color: var(--accent-link);
    background: var(--tint);
  }
  .sync-conflict-head {
    color: var(--text-heading);
    font-size: var(--type-3);
    font-weight: 650;
  }
  .sync-conflict-meta {
    color: var(--text-muted);
    font-size: var(--type-1);
  }
  .sync-conflict-count {
    margin-top: var(--space-2);
    color: var(--text-2);
    font-size: var(--type-2);
  }
  .sync-warning {
    margin: 0;
    color: var(--warn-text);
    font-size: var(--type-2);
    line-height: 1.5;
  }
  @media (max-width: 560px) {
    .sync-conflict-grid { grid-template-columns: 1fr; }
  }
</style>

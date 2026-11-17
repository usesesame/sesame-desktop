<script lang="ts">
  import { changedSince, pendingChangeMessage } from '../controllers/pending-changes-controller'
  import type { PendingChangeView } from '../types'

  export let changes: PendingChangeView[] = []
  export let working: string | null = null
  export let label = 'Passwords waiting for you'
  export let placement: 'vault' | 'login' = 'vault'
  export let onKeep: (change: PendingChangeView) => void
  export let onGoBack: (change: PendingChangeView) => void
  export let onDiscard: (change: PendingChangeView) => void
  export let onCopy: (change: PendingChangeView) => void
  export let onEdit: (change: PendingChangeView) => void
  export let onOpenHistory: (change: PendingChangeView) => void = () => {}

  const suggestsGoingBack = (change: PendingChangeView) => change.kind === 'change' && change.fill === 'notFilled' && change.canGoBack
</script>

{#if changes.length}
  <section class="pending-changes {placement}" aria-label={label}>
    {#each changes as change (change.id)}
      <div class="pending-change" class:attention={change.urgent || change.fill === 'notFilled'} aria-busy={working === change.id}>
        <p>{pendingChangeMessage(change)}</p>
        <div class="pending-change-actions">
          {#if change.kind === 'new'}
            <button type="button" class="secondary-button" disabled={working !== null} on:click={() => onKeep(change)}>Keep login</button>
            <button type="button" class="text-button" disabled={working !== null} on:click={() => onEdit(change)}>Edit</button>
            <button type="button" class="text-button" disabled={working !== null} on:click={() => onCopy(change)}>Copy password</button>
            <button type="button" class="text-button" disabled={working !== null} on:click={() => onDiscard(change)}>Move to Trash</button>
          {:else if changedSince(change)}
            <button type="button" class="secondary-button" disabled={working !== null} on:click={() => onOpenHistory(change)}>Open history</button>
            <button type="button" class="text-button" disabled={working !== null} on:click={() => onKeep(change)}>Dismiss</button>
          {:else if suggestsGoingBack(change)}
            <button type="button" class="secondary-button" disabled={working !== null} on:click={() => onGoBack(change)}>Go back to old password</button>
            <button type="button" class="text-button" disabled={working !== null} on:click={() => onKeep(change)}>Keep new password</button>
          {:else}
            <button type="button" class="secondary-button" disabled={working !== null} on:click={() => onKeep(change)}>Keep new password</button>
            {#if change.canGoBack}<button type="button" class="text-button" disabled={working !== null} on:click={() => onGoBack(change)}>Go back to old password</button>{/if}
            <button type="button" class="text-button" disabled={working !== null} on:click={() => onCopy(change)}>Copy password</button>
          {/if}
        </div>
      </div>
    {/each}
  </section>
{/if}

<style>
  .pending-changes {
    display: grid;
    flex: none;
    border-top: 1px solid var(--border-soft);
  }

  .pending-changes.vault {
    width: min(100%, var(--content-width));
    margin: 0 auto var(--space-4);
  }

  .pending-changes.login {
    margin: var(--space-4) 0 0;
  }

  .pending-change {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2) var(--space-4);
    border-bottom: 1px solid var(--border-soft);
    padding: var(--space-3) 0;
  }

  .pending-change p {
    flex: 1 1 280px;
    margin: 0;
    color: var(--text);
    font-size: var(--type-3);
    line-height: 1.5;
  }

  .pending-change.attention p {
    color: var(--warn-text);
  }

  .pending-change-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2) var(--space-3);
  }
</style>

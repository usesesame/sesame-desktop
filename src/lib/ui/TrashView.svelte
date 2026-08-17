<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { ItemPreview, TrashSummary } from '../types'

  export let items: TrashSummary[] = []
  export let restoringId: string | null = null
  export let previewingId: string | null = null
  export let previewId: string | null = null
  export let preview: ItemPreview | null = null
  export let onPreview: (id: string) => void
  export let onCancelPreview: () => void
  export let onRestore: (id: string) => void

  function daysLeft(deletedAt: number): number {
    const retentionSeconds = 30 * 24 * 60 * 60
    const elapsed = Math.floor(Date.now() / 1000) - deletedAt
    return Math.max(0, Math.ceil((retentionSeconds - elapsed) / 86_400))
  }
</script>

<section class="trash-view">
  {#if !items.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md trash-empty-icon"><Icon name="trash" size={32} /></span>
      <p class="eyebrow">Nothing here</p>
      <h2>Trash is empty.</h2>
      <p>A deleted login, identity, or other saved item stays here for 30 days before Sesame removes it for good.</p>
    </section>
  {:else}
    <ul class="trash-list">
      {#each items as item (item.id)}
        <li class="trash-row">
          <span class="entry-avatar"><Icon name="trash" size={15} /></span>
          {#if previewId === item.id && preview}
            <div class="trash-row-detail">
              <strong>{preview.title}</strong>
              <small>{preview.detail ? `${preview.detail} · ` : ''}{daysLeft(item.deletedAt)} {daysLeft(item.deletedAt) === 1 ? 'day' : 'days'} left</small>
            </div>
            <div class="trash-row-actions">
              <button type="button" class="secondary-button" on:click={onCancelPreview}>Cancel</button>
              <button
                type="button"
                class="primary-button"
                disabled={restoringId === item.id}
                on:click={() => onRestore(item.id)}
              >
                {restoringId === item.id ? 'Restoring…' : 'Restore'}
              </button>
            </div>
          {:else}
            <div class="trash-row-detail">
              <strong>Deleted {item.kind.replaceAll('_', ' ')}</strong>
              <small>{daysLeft(item.deletedAt)} {daysLeft(item.deletedAt) === 1 ? 'day' : 'days'} left</small>
            </div>
            <div class="trash-row-actions">
              <button
                type="button"
                class="icon-button"
                aria-label={`Preview deleted ${item.kind.replaceAll('_', ' ')} before restoring`}
                title="Preview before restoring"
                disabled={previewingId === item.id}
                on:click={() => onPreview(item.id)}
              >
                <Icon name={previewingId === item.id ? 'refresh' : 'eye'} size={15} />
              </button>
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

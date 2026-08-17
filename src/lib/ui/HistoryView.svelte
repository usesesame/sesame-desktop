<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { HistorySummary, ItemPreview } from '../types'

  export let items: HistorySummary[] = []
  export let restoringId: string | null = null
  export let previewingId: string | null = null
  export let previewId: string | null = null
  export let preview: ItemPreview | null = null
  export let onPreview: (id: string) => void
  export let onCancelPreview: () => void
  export let onRestore: (id: string) => void
  export let titleFor: (kind: string, itemId: string) => string | null = () => null

  interface HistoryGroup {
    itemId: string
    kind: string
    versions: HistorySummary[]
  }

  let collapsed: Record<string, boolean> = {}

  function toggle(itemId: string) {
    collapsed = { ...collapsed, [itemId]: !collapsed[itemId] }
  }

  function formatWhen(capturedAt: number): string {
    return new Date(capturedAt * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  }

  $: groups = items.reduce<HistoryGroup[]>((groups, item) => {
    const group = groups.find((candidate) => candidate.itemId === item.itemId)
    if (group) {
      group.versions.push(item)
    } else {
      groups.push({ itemId: item.itemId, kind: item.kind, versions: [item] })
    }
    return groups
  }, [])
</script>

<section class="history-view">
  {#if !items.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md history-empty-icon"><Icon name="refresh" size={32} /></span>
      <p class="eyebrow">Nothing here</p>
      <h2>No saved versions yet.</h2>
      <p>Editing a saved item keeps its previous version here for 30 days, so an unwanted change can be undone.</p>
    </section>
  {:else}
    <ul class="history-groups">
      {#each groups as group (group.itemId)}
        <li class="history-group">
          <button
            type="button"
            class="history-group-header"
            aria-expanded={!collapsed[group.itemId]}
            on:click={() => toggle(group.itemId)}
          >
            <span class="entry-avatar"><Icon name="refresh" size={15} /></span>
            <div class="history-row-detail">
              <strong>{titleFor(group.kind, group.itemId) ?? `Removed ${group.kind.replaceAll('_', ' ')}`}</strong>
              <small>{group.versions.length} saved {group.versions.length === 1 ? 'version' : 'versions'}</small>
            </div>
            <span class="history-group-chevron" class:expanded={!collapsed[group.itemId]}>
              <Icon name="chevron-right" size={15} />
            </span>
          </button>
          {#if !collapsed[group.itemId]}
            <ul class="history-list">
              {#each group.versions as item (item.id)}
                <li class="history-row">
                  {#if previewId === item.id && preview}
                    <div class="history-row-detail">
                      <strong>{preview.title}</strong>
                      <small>{preview.detail ? `${preview.detail} · ` : ''}Saved {formatWhen(item.capturedAt)}</small>
                    </div>
                    <div class="history-row-actions">
                      <button type="button" class="secondary-button" on:click={onCancelPreview}>Cancel</button>
                      <button
                        type="button"
                        class="primary-button"
                        disabled={restoringId === item.id}
                        on:click={() => onRestore(item.id)}
                      >
                        {restoringId === item.id ? 'Restoring…' : 'Restore this version'}
                      </button>
                    </div>
                  {:else}
                    <div class="history-row-detail">
                      <small>Saved {formatWhen(item.capturedAt)}</small>
                    </div>
                    <div class="history-row-actions">
                      <button
                        type="button"
                        class="icon-button"
                        aria-label={`Preview this ${item.kind.replaceAll('_', ' ')} version before restoring`}
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
        </li>
      {/each}
    </ul>
  {/if}
</section>

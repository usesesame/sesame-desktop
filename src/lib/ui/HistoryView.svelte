<script lang="ts">
  import Icon from '../Icon.svelte'
  import ViewHeader from './ViewHeader.svelte'
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

  // Closed by default: a long history is a wall of rows when every item is open.
  let expanded: Record<string, boolean> = {}

  function toggle(itemId: string) {
    expanded = { ...expanded, [itemId]: !expanded[itemId] }
  }

  function formatWhen(capturedAt: number): string {
    return new Date(capturedAt * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  }

  function relativeWhen(capturedAt: number): string {
    const seconds = Math.max(0, Math.floor(Date.now() / 1_000) - capturedAt)
    if (seconds < 60) return 'just now'
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`
    const days = Math.floor(hours / 24)
    return `${days} ${days === 1 ? 'day' : 'days'} ago`
  }

  // Reads as a sentence, so a row says what it was rather than only when it was.
  function changeSummary(changed: string[]): string {
    if (!changed.length) return 'No field changed'
    if (changed.length === 1) return `${changed[0]} changed`
    if (changed.length === 2) return `${changed[0]} and ${changed[1]} changed`
    return `${changed.slice(0, 2).join(', ')} and ${changed.length - 2} more changed`
  }

  function kindLabel(kind: string): string {
    return kind.replaceAll('_', ' ')
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
  <ViewHeader title="History" />
  {#if !items.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md history-empty-icon"><Icon name="refresh" size={32} /></span>
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
            aria-expanded={expanded[group.itemId] === true}
            on:click={() => toggle(group.itemId)}
          >
            <span class="entry-avatar"><Icon name="refresh" size={15} /></span>
            <div class="history-row-detail">
              <strong>{titleFor(group.kind, group.itemId) ?? `Removed ${group.kind.replaceAll('_', ' ')}`}</strong>
              <small>{kindLabel(group.kind)} · {group.versions.length} saved {group.versions.length === 1 ? 'version' : 'versions'} · last {relativeWhen(group.versions[0].capturedAt)}</small>
            </div>
            <span class="history-group-chevron" class:expanded={expanded[group.itemId] === true}>
              <Icon name="chevron-right" size={15} />
            </span>
          </button>
          {#if expanded[group.itemId]}
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
                      <strong class="history-change">{changeSummary(item.changed)}</strong>
                      <small title={formatWhen(item.capturedAt)}>{relativeWhen(item.capturedAt)} · {formatWhen(item.capturedAt)}</small>
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

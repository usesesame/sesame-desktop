<script lang="ts">
  import { entryDetails, entrySentence, isRefusal, type TitleLookup } from '../release-record'
  import type { ReleaseEntryView } from '../types'

  export let entries: ReleaseEntryView[]
  export let titleFor: TitleLookup
  export let onOpenItem: ((itemId: string) => void) | null = null
  export let withDate = false

  function openable(entry: ReleaseEntryView): boolean {
    return Boolean(onOpenItem && entry.itemId && titleFor(entry.itemKind ?? '', entry.itemId))
  }
</script>

<ul class="activity-rows">
  {#each entries as entry (entry.seq + ':' + entry.at)}
    <li class="activity-row" class:refused={isRefusal(entry.outcome)}>
      {#if openable(entry)}
        <button type="button" class="activity-row-body" on:click={() => entry.itemId && onOpenItem?.(entry.itemId)}>
          <span class="activity-sentence">{entrySentence(entry, titleFor)}</span>
          <small>{entryDetails(entry, withDate)}</small>
        </button>
      {:else}
        <div class="activity-row-body">
          <span class="activity-sentence">{entrySentence(entry, titleFor)}</span>
          <small>{entryDetails(entry, withDate)}</small>
        </div>
      {/if}
    </li>
  {/each}
</ul>

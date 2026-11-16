<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import ReleaseRecordRows from './ReleaseRecordRows.svelte'
  import { getReleaseRecord, onReleaseRecordChanged } from '../release-record-api'
  import { itemNoun, thisItem } from '../release-record'
  import type { ReleaseEntryView } from '../types'

  export let itemId: string
  export let itemKind: string
  export let onShowAll: (itemId: string, itemKind: string) => void = () => {}

  const RECENT = 5
  let entries: ReleaseEntryView[] = []
  let total = 0
  let loadedFor = ''
  let unlisten: (() => void) | null = null

  async function load(id: string) {
    try {
      const page = await getReleaseRecord({ itemId: id, limit: RECENT })
      if (id !== itemId) return
      entries = page.entries
      total = page.total
      loadedFor = id
    } catch {
      entries = []
      total = 0
      loadedFor = id
    }
  }

  $: if (itemId) void load(itemId)

  onMount(() => {
    void onReleaseRecordChanged(() => void load(itemId)).then((stop) => { unlisten = stop })
  })

  onDestroy(() => unlisten?.())

  function titleFor(): string {
    return thisItem(itemKind)
  }
</script>

<section class="details-section item-activity">
  <div class="section-heading">
    <h3>Recent activity</h3>
    {#if total > entries.length}<button type="button" class="text-button" on:click={() => onShowAll(itemId, itemKind)}>Show all</button>{/if}
  </div>
  {#if loadedFor === itemId && !entries.length}
    <p class="item-notes">Sesame has not released this {itemNoun(itemKind)} since the activity record began.</p>
  {:else if entries.length}
    <ReleaseRecordRows {entries} {titleFor} withDate />
  {/if}
</section>

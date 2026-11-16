<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import ViewHeader from './ViewHeader.svelte'
  import SelectMenu from './SelectMenu.svelte'
  import ReleaseRecordRows from './ReleaseRecordRows.svelte'
  import { getReleaseRecord, onReleaseRecordChanged } from '../release-record-api'
  import { RECORD_SCOPE_TEXT, activityItemFilter, groupByDay, itemTitle, longDate, statusNotice, type TitleLookup } from '../release-record'
  import type { ReleaseEntryView, ReleaseRecordStatus } from '../types'

  export let titleFor: TitleLookup
  export let onOpenItem: (itemId: string) => void = () => {}

  const PAGE = 200
  const filterOptions = [
    { value: 'all', label: 'All activity' },
    { value: 'refused', label: 'Refused and unanswered' },
  ]

  let filter = 'all'
  let entries: ReleaseEntryView[] = []
  let total = 0
  let status: ReleaseRecordStatus | null = null
  let loading = true
  let failed = ''
  let unlisten: (() => void) | null = null

  async function load(limit = PAGE) {
    try {
      const page = await getReleaseRecord({ refusedOnly: filter === 'refused', limit, itemId: $activityItemFilter?.itemId })
      entries = page.entries
      total = page.total
      status = page.status
      failed = ''
    } catch (error) {
      failed = error instanceof Error ? error.message : 'Sesame could not read the activity record.'
    } finally {
      loading = false
    }
  }

  function clearItemFilter() {
    activityItemFilter.set(null)
    void load()
  }

  function setFilter(next: string) {
    filter = next
    void load()
  }

  onMount(() => {
    void load()
    void onReleaseRecordChanged(() => void load(Math.max(PAGE, entries.length))).then((stop) => { unlisten = stop })
  })

  onDestroy(() => {
    unlisten?.()
    activityItemFilter.set(null)
  })

  $: days = groupByDay(entries)
  $: notice = statusNotice(status)
</script>

<section class="activity-view">
  <ViewHeader title="Activity">
    <div slot="aside" class="view-header-aside" class:none={!status?.startsAt}>
      {#if status?.startsAt}<span>Since {longDate(status.startsAt)}</span>{/if}
    </div>
  </ViewHeader>

  {#if notice}<p class="activity-notice" role="status">{notice}</p>{/if}

  <div class="activity-toolbar">
    {#if $activityItemFilter}
      <p class="activity-scope-line">Showing activity for {itemTitle($activityItemFilter, titleFor)}. <button type="button" class="text-button" on:click={clearItemFilter}>Show all activity</button></p>
    {/if}
    <SelectMenu label="Show" value={filter} options={filterOptions} onChange={setFilter} />
  </div>

  {#if failed}
    <p class="activity-empty" role="alert">{failed}</p>
  {:else if loading}
    <p class="activity-empty" aria-live="polite">Reading the activity record.</p>
  {:else if !entries.length}
    <p class="activity-empty">{filter === 'refused' ? 'No refused or unanswered requests are in the record.' : 'Nothing has left the vault since the record began.'}</p>
  {:else}
    <ul class="activity-list" aria-label="Activity">
      {#each days as day (day.key)}
        <li class="activity-day">
          <h3>{day.label}</h3>
          <ReleaseRecordRows entries={day.entries} {titleFor} {onOpenItem} />
        </li>
      {/each}
    </ul>
    {#if total > entries.length}
      <button type="button" class="text-button activity-more" on:click={() => void load(entries.length + PAGE)}>Show older activity</button>
    {/if}
  {/if}

  <div class="activity-scope">
    <h3>About this list</h3>
    {#each RECORD_SCOPE_TEXT as paragraph (paragraph)}<p>{paragraph}</p>{/each}
  </div>
</section>

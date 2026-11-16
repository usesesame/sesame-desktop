<script lang="ts">
  import { onMount } from 'svelte'
  import { slidingSelection } from './sliding-selection'
  import { getReleaseRecordStatus, setReleaseRecordRetention } from '../release-record-api'

  export let onClear: (done: () => void) => Promise<void>

  const RETENTION_CHOICES = [30, 90, 180, 365]

  let retentionDays = 180
  let working = false
  let confirming = false
  let errorMessage = ''

  onMount(() => {
    void getReleaseRecordStatus().then((status) => { retentionDays = status.retentionDays }).catch(() => {})
  })

  async function choose(days: number) {
    if (working || days === retentionDays) return
    working = true
    errorMessage = ''
    try {
      retentionDays = (await setReleaseRecordRetention(days)).retentionDays
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : 'Sesame could not change how long it keeps activity.'
    } finally {
      working = false
    }
  }

  async function clear() {
    working = true
    try {
      await onClear(() => { confirming = false })
    } finally {
      working = false
    }
  }
</script>

<section class="settings-group" aria-labelledby="settings-group-activity">
  <h3 id="settings-group-activity">Activity</h3>
  <div class="settings-list">
    <article>
      <div class="setting-copy"><strong>Keep activity for</strong><p>Sesame removes entries older than this from the activity record on this device.</p></div>
      <div class="clipboard-clear-options" role="group" aria-label="How long Sesame keeps activity" use:slidingSelection>{#each RETENTION_CHOICES as days (days)}<button type="button" class:active={retentionDays === days} aria-pressed={retentionDays === days} aria-label={`${days} days`} disabled={working} on:click={() => void choose(days)}>{days}d</button>{/each}</div>
    </article>
    <article>
      {#if confirming}
        <div class="setting-copy"><strong>Clear the activity record?</strong><p>Sesame removes every entry and keeps one that says the record was cleared. It asks for your master password first.</p></div>
        <div class="diagnostic-actions"><button type="button" class="text-button" disabled={working} on:click={() => (confirming = false)}>Cancel</button><button type="button" class="secondary-button settings-manage" disabled={working} on:click={() => void clear()}>Clear record</button></div>
      {:else}
        <div class="setting-copy"><strong>Clear activity</strong><p>Remove every entry from the activity record on this device.</p></div>
        <button type="button" class="secondary-button settings-manage" disabled={working} on:click={() => (confirming = true)}>Clear</button>
      {/if}
    </article>
    {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
  </div>
</section>

<script lang="ts">
  import { onMount } from 'svelte'
  import Icon from '../Icon.svelte'
  import { createSyncPreviewController } from '../controllers/sync-preview-controller'

  const syncPreview = createSyncPreviewController()

  onMount(() => {
    void syncPreview.refresh()
  })

  // Nothing has been uploaded until another device approves this one.
  $: syncing = $syncPreview.enrolled && $syncPreview.state === 'approved'
</script>

<article>
  <span class="settings-icon"><Icon name={syncing ? 'refresh' : 'shield'} size={17} /></span>
  <div class="setting-copy">
    {#if syncing}
      <strong>Synced vault</strong>
      <p>
        This device holds your vault, and Sesame Sync holds an encrypted copy so
        your other devices can read it. Sesame cannot read that copy.
      </p>
    {:else}
      <strong>Local-only vault</strong>
      <p>Your vault is stored on this device. Sesame has no cloud copy.</p>
    {/if}
  </div>
  <span class="status-pill">{syncing ? 'Synced' : 'Active'}</span>
</article>

<script lang="ts">
  import { syncController as syncPanel } from '../sync'

  // Nothing has been uploaded until another device approves this one.
  $: syncing = $syncPanel.enrolled && $syncPanel.state === 'approved'
</script>

<article>
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

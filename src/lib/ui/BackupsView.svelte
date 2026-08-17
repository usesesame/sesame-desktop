<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { RecoveryHealth } from '../types'

  export let health: RecoveryHealth | null = null
  export let currentRevision: number = 0
  export let onExportBackup: () => void
  export let onBeginRestore: () => void
  export let onMakeBackup: () => void
  export let onOpenDrill: () => void
  export let onOpenSwitchingJourney: () => void

  function formatDate(iso: string | undefined): string {
    if (!iso) return 'never'
    const date = new Date(iso)
    return isNaN(date.getTime()) ? iso : date.toLocaleString()
  }

  $: exported = health?.lastExportedRevision === currentRevision
  $: verified = health?.lastVerifiedRevision === currentRevision
  $: status = verified ? 'good' : exported ? 'attention' : 'missing'
  $: statusMessage = verified
    ? 'Your backup is up to date and verified.'
    : exported
      ? 'Your backup is current, but the recovery drill has not been completed.'
      : 'No current backup has been recorded.'
</script>

<section class="backups-view">
  <p class="lede">A Sesame backup is encrypted. Keep one somewhere separate from this computer.</p>
  {#if health}
    <div class="recovery-health recovery-health-{status}">
      <strong>Recovery health</strong>
      <span>{statusMessage}</span>
      <span class="recovery-health-meta">Last export: {formatDate(health.lastExportedAt)} · Last verified: {formatDate(health.lastVerifiedAt)}</span>
    </div>
  {/if}
  <div class="backup-list">
    <article class="backup-card"><span class="backup-icon"><Icon name="archive" size={25} /></span><div><h3>Export an encrypted backup</h3><p>Choose where to save a copy of your vault.</p></div><button type="button" class="primary-button" on:click={onExportBackup}>Export backup <Icon name="chevron-right" size={16} /></button></article>
    <article class="backup-card"><span class="backup-icon"><Icon name="shield" size={24} /></span><div><h3>Run a recovery drill</h3><p>Open a backup without changing your vault, then optionally test the full restore.</p></div><button type="button" class="secondary-button" on:click={onOpenDrill}>Test a backup</button></article>
    <article class="backup-card"><span class="backup-icon"><Icon name="refresh" size={24} /></span><div><h3>Restore from a backup</h3><p>Checks the file and keeps a safety copy of the current vault before replacing it.</p></div><button type="button" class="secondary-button" on:click={onBeginRestore}>Choose backup</button></article>
  </div>
  <button type="button" class="text-button backup-local-copy" on:click={onMakeBackup}>Also keep a local copy</button>
  <button type="button" class="text-button backup-local-copy" on:click={onOpenSwitchingJourney}>Open switching guide</button>
  <div class="backup-reminder"><strong>Before you rely on Sesame:</strong><span>Keep two copies in separate places and complete a recovery drill.</span></div>
</section>

<style>
  .recovery-health {
    margin: 1rem 0;
    padding: 0.75rem 1rem;
    border-radius: 0.5rem;
    background: var(--surface-2, #f5f5f5);
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .recovery-health-good {
    border-left: 0.25rem solid var(--ok-text);
  }

  .recovery-health-attention {
    border-left: 0.25rem solid var(--warn-text);
  }

  .recovery-health-missing {
    border-left: 0.25rem solid var(--danger);
  }

  .recovery-health-meta {
    font-size: 0.875rem;
    opacity: 0.8;
  }
</style>

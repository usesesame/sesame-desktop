<script lang="ts">
  import Icon from '../Icon.svelte'
  import ViewHeader from './ViewHeader.svelte'
  import type { RecoveryHealth } from '../types'

  export let health: RecoveryHealth | null = null
  export let currentRevision: number = 0
  export let exportPresenceRequired = false
  export let exportPresencePassword = ''
  export let errorMessage = ''
  export let onExportBackup: () => void
  export let onConfirmPresence: () => void
  export let onBeginRestore: () => void
  export let onMakeBackup: () => void
  export let onOpenDrill: () => void

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
  <ViewHeader title="Backups" />
  {#if health}
    <div class="recovery-health recovery-health-{status}">
      <p class="recovery-health-head"><span class="recovery-health-dot" aria-hidden="true"></span><strong>Recovery health</strong><span class="recovery-health-meta">Last export: {formatDate(health.lastExportedAt)} · Last verified: {formatDate(health.lastVerifiedAt)}</span></p>
      <p class="recovery-health-message">{statusMessage}</p>
    </div>
  {/if}
  <div class="backup-list">
    <article class="backup-card"><span class="backup-icon"><Icon name="archive" size={25} /></span><div><h3>Export an encrypted backup</h3><p>Choose where to save a copy of your vault.</p></div><button type="button" class="primary-button" on:click={onExportBackup}>Export backup <Icon name="chevron-right" size={16} /></button></article>
    {#if exportPresenceRequired}
      <article class="backup-card">
        <form class="presence-confirm" novalidate on:submit|preventDefault={onConfirmPresence}>
          <label class="delete-vault-input" for="backup-presence-password">Master password</label>
          <p class="backup-presence-note">Sesame asks for your master password before it writes a copy of your vault to a file.</p>
          <input
            id="backup-presence-password"
            name="backup-presence-password"
            type="password"
            bind:value={exportPresencePassword}
            autocomplete="current-password"
            spellcheck="false"
            aria-invalid={Boolean(errorMessage)}
            aria-describedby={errorMessage ? 'backup-presence-error' : undefined}
          />
          {#if errorMessage}<p id="backup-presence-error" class="form-error" role="alert">{errorMessage}</p>{/if}
          <div class="confirm-actions">
            <button type="submit" class="primary-button" disabled={!exportPresencePassword}>Confirm and export</button>
          </div>
        </form>
      </article>
    {/if}
    <article class="backup-card"><span class="backup-icon"><Icon name="shield" size={24} /></span><div><h3>Run a recovery drill</h3><p>Open a backup without changing your vault, then optionally test the full restore.</p></div><button type="button" class="secondary-button" on:click={onOpenDrill}>Test a backup</button></article>
    <article class="backup-card"><span class="backup-icon"><Icon name="refresh" size={24} /></span><div><h3>Restore from a backup</h3><p>Checks the file and keeps a safety copy of the current vault before replacing it.</p></div><button type="button" class="secondary-button" on:click={onBeginRestore}>Choose backup</button></article>
  </div>
  <button type="button" class="text-button backup-local-copy" on:click={onMakeBackup}>Also keep a local copy</button>
  <div class="backup-reminder"><strong>Before you rely on Sesame:</strong><span>Keep two copies in separate places and complete a recovery drill.</span></div>
</section>

<style>
  .presence-confirm { display: grid; gap: var(--space-1); }
  .backup-presence-note { margin: 0; color: var(--text-muted); font-size: var(--type-1); }
  .presence-confirm input {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface);
    color: var(--text);
  }
  .recovery-health {
    display: grid;
    gap: var(--space-1);
    margin: 0 0 var(--space-4);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-raised);
  }
  .recovery-health-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
    margin: 0;
  }
  .recovery-health-dot {
    width: 8px;
    height: 8px;
    flex: none;
    border-radius: 50%;
    background: var(--text-faint);
  }
  .recovery-health-good .recovery-health-dot { background: var(--ok-text); }
  .recovery-health-attention .recovery-health-dot { background: var(--warn-text); }
  .recovery-health-missing .recovery-health-dot { background: var(--danger); }
  .recovery-health-head strong { color: var(--text-heading); font-size: var(--type-2); }
  .recovery-health-meta { margin-left: auto; color: var(--text-muted); font-size: var(--type-1); }
  .recovery-health-message { margin: 0; color: var(--text-muted); font-size: var(--type-2); }
</style>

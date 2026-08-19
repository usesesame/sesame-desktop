<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { BrowserIntegrationStatus, RecoveryHealth } from '../types'
  import ModalShell from './ModalShell.svelte'
  import { readSwitchingChecklist, storeSwitchingChecklist } from '../preferences'

  export let health: RecoveryHealth | null = null
  export let currentRevision = 0
  export let browserIntegration: BrowserIntegrationStatus | null = null
  export let onClose: () => void
  export let onOpenBackups: () => void
  export let onImport: () => void
  export let onOpenSettings: () => void

  $: backupReady = health?.lastExportedRevision === currentRevision || health?.lastVerifiedRevision === currentRevision
  $: browserReady = browserIntegration?.ready === true
  const checklist = readSwitchingChecklist()

  $: storeSwitchingChecklist(checklist)

  function openBackups() {
    onClose()
    onOpenBackups()
  }

  function importVault() {
    if (!backupReady) return
    onClose()
    onImport()
  }

  function openSettings() {
    onClose()
    onOpenSettings()
  }
</script>

<ModalShell onClose={onClose} labelledby="switching-journey-heading" describedby="switching-journey-description" tone="switching-journey">
  <span class="switching-journey-icon"><Icon name="archive" size={21} /></span>
  <p class="eyebrow">Switching guide</p>
  <h2 id="switching-journey-heading">Move to Sesame in small steps</h2>
  <p id="switching-journey-description">Keep your current password manager available for 14 days while you verify that Sesame has the logins you need.</p>

  <ol class="switching-steps">
    <li class:complete={backupReady}>
      <strong>{backupReady ? 'Backup ready' : 'Create or verify a backup'}</strong>
      <span>{backupReady ? 'Your current vault revision has a backup record.' : 'Export an encrypted backup or complete a recovery drill before importing.'}</span>
      {#if !backupReady}<button type="button" class="secondary-button" on:click={openBackups}>Open backups</button>{/if}
    </li>
    <li>
      <strong>Import a copy of your existing vault</strong>
      <span>Sesame previews preserved, transformed, unsupported, and malformed fields before you commit an import. The export stays on this device.</span>
      <button type="button" class="primary-button" disabled={!backupReady} on:click={importVault}>Import vault</button>
    </li>
    <li class:complete={browserReady}>
      <strong>{browserReady ? 'Sesame browser connection is ready' : 'Check your browser setup'}</strong>
      <span>{browserReady ? 'Use Sesame alongside your current manager during the dual-run period.' : 'Sesame cannot inspect or change browser password-saving settings or other extensions. Check them yourself before relying on browser fill.'}</span>
      <button type="button" class="secondary-button" on:click={openSettings}>Open browser settings</button>
    </li>
    <li>
      <strong>Use both managers for 14 days</strong>
      <span>Keep the old manager enabled until these checks are complete.</span>
      <div class="dual-run-checklist" aria-label="14-day dual-run checklist">
        <label><input type="checkbox" bind:checked={checklist.regularSites} /> Test your regular sites</label>
        <label><input type="checkbox" bind:checked={checklist.recoveryDetails} /> Check recovery details</label>
        <label><input type="checkbox" bind:checked={checklist.browserFill} /> Test browser fill</label>
        <label><input type="checkbox" bind:checked={checklist.dualRun} /> Keep both managers available for 14 days</label>
      </div>
    </li>
  </ol>

  <p class="switching-note">If a step cannot run, Sesame leaves your vault and browser settings unchanged. Use the named action above or keep using your current manager.</p>
  <div class="switching-actions"><button type="button" class="secondary-button" on:click={onClose}>Close guide</button></div>
</ModalShell>

<style>
  .switching-journey-icon { display: inline-grid; place-items: center; width: 2.5rem; height: 2.5rem; border-radius: 50%; color: var(--accent-link); background: var(--tint); }
  .switching-steps { display: grid; gap: var(--space-3); margin: var(--space-5) 0; padding: 0; list-style: none; counter-reset: step; }
  /* The marker is a real column, so the title no longer needs pulling up over it. */
  .switching-steps li {
    display: grid;
    grid-template-columns: 1.5rem minmax(0, 1fr);
    align-items: start;
    gap: var(--space-2) var(--space-3);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    background: var(--surface-2);
  }
  .switching-steps li::before {
    counter-increment: step;
    content: counter(step);
    display: grid;
    grid-column: 1;
    width: 1.5rem;
    height: 1.5rem;
    place-items: center;
    border-radius: var(--radius-pill);
    background: var(--surface-3);
    color: var(--text-2);
    font-size: var(--type-1);
    font-weight: 700;
  }
  .switching-steps li.complete::before { content: '✓'; background: var(--ok-bg); color: var(--ok-text); }
  .switching-steps strong { grid-column: 2; color: var(--text-heading); font-size: var(--type-2); }
  .switching-steps span { grid-column: 2; color: var(--text-muted); font-size: var(--type-2); line-height: 1.5; }
  .switching-steps button { grid-column: 2; justify-self: start; margin-top: var(--space-1); }
  .dual-run-checklist { display: grid; grid-column: 2; gap: var(--space-2); margin-top: var(--space-1); }
  .dual-run-checklist label { display: flex; align-items: flex-start; gap: var(--space-2); color: var(--text); font-size: var(--type-2); }
  .dual-run-checklist input { width: 16px; height: 16px; flex: none; margin-top: 2px; accent-color: var(--accent); }
  .switching-note { color: var(--text-muted); font-size: var(--type-1); line-height: 1.55; }
  .switching-actions { display: flex; justify-content: flex-end; margin-top: var(--space-5); }
</style>

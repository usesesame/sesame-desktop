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
  .switching-steps { display: grid; gap: 0.75rem; margin: 1.25rem 0; padding: 0; list-style: none; counter-reset: step; }
  .switching-steps li { display: grid; gap: 0.35rem; padding: 0.9rem; border: 1px solid var(--border); border-radius: 0.6rem; background: var(--surface-2); }
  .switching-steps li::before { counter-increment: step; content: counter(step); width: 1.45rem; height: 1.45rem; display: grid; place-items: center; border-radius: 50%; background: var(--surface-3); font-size: 0.8rem; font-weight: 700; }
  .switching-steps li.complete::before { content: '✓'; background: var(--ok-bg); color: var(--ok-text); }
  .switching-steps strong { margin-top: -1.75rem; margin-left: 2rem; }
  .switching-steps span { color: var(--text-muted); }
  .switching-steps button { justify-self: start; margin-top: 0.2rem; }
  .dual-run-checklist { display: grid; gap: 0.4rem; margin-top: 0.2rem; }
  .dual-run-checklist label { display: flex; align-items: flex-start; gap: 0.5rem; color: var(--text); }
  .dual-run-checklist input { margin-top: 0.2rem; accent-color: var(--accent); }
  .switching-note { color: var(--text-muted); font-size: 0.9rem; }
  .switching-actions { display: flex; justify-content: flex-end; margin-top: 1.25rem; }
</style>

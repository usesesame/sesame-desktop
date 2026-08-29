<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { BackupSelection } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let selection: BackupSelection | null = null
  export let secret = ''
  export let verification: { fileName: string; formatVersion: number; vaultName: string; entryCount: number } | null = null
  export let working = false
  export let restoring = false
  export let error = ''
  export let onChoose: () => void
  export let onVerify: () => void
  export let onRestore: () => void
  export let onClose: () => void

  let secretInput: HTMLInputElement

  $: step = verification ? 3 : selection ? 2 : 1

  function focusInitial() {
    if (selection && !verification) secretInput?.focus()
  }
</script>

<ModalShell
  onClose={() => !working && !restoring && onClose()}
  labelledby="backup-drill-heading"
  describedby="backup-drill-description"
  modalClass="backup-drill-modal"
  ariaBusy={working || restoring}
  initialFocus={focusInitial}
>
  <button type="button" class="modal-close" disabled={working || restoring} on:click={onClose} aria-label="Close backup drill">×</button>
  <span class="confirm-icon"><Icon name="shield" size={20} /></span>
  <p class="eyebrow">Recovery drill</p>
  <h2 id="backup-drill-heading">Prove your backup opens.</h2>
  <p id="backup-drill-description">Sesame verifies the encrypted copy before offering to restore it. Nothing is replaced during verification.</p>

  <ol class="drill-steps" aria-label="Backup drill progress">
    <li class:current={step === 1} class:complete={step > 1}><span>{step > 1 ? '✓' : '1'}</span><div><strong>Choose</strong><small>Select an encrypted .sesame backup</small></div></li>
    <li class:current={step === 2} class:complete={step > 2}><span>{step > 2 ? '✓' : '2'}</span><div><strong>Verify</strong><small>Open it without changing your vault</small></div></li>
    <li class:current={step === 3}><span>3</span><div><strong>Restore</strong><small>Optional final recovery test</small></div></li>
  </ol>

  {#if !selection}
    <div class="drill-action-panel">
      <Icon name="archive" size={22} />
      <div><strong>Choose your encrypted backup</strong><p>Use a copy stored outside Sesame's local backup folder.</p></div>
      <button type="button" class="primary-button" on:click={onChoose}>Choose backup</button>
    </div>
  {:else if !verification}
    <div class="drill-file"><Icon name="archive" size={17} /><div><strong>{selection.fileName}</strong><small>Vault format {selection.formatVersion}</small></div><button type="button" class="text-button" disabled={working} on:click={onChoose}>Change</button></div>
    <label class="drill-secret">Master password or recovery kit<input bind:this={secretInput} name="backup-drill-secret" bind:value={secret} type="password" autocomplete="off" spellcheck="false" disabled={working} /></label>
    <p class="drill-privacy"><Icon name="shield" size={14} /> Used locally for this check and cleared when the drill closes.</p>
    {#if error}<p class="field-error" role="alert">{error}</p>{/if}
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={working} on:click={onClose}>Cancel</button><button type="button" class="primary-button" disabled={working || !secret.trim()} on:click={onVerify}>{working ? 'Verifying…' : 'Verify backup'}</button></div>
  {:else}
    <div class="drill-result" role="status">
      <span><Icon name="check" size={19} /></span>
      <div><strong>This backup opened successfully.</strong><p><b>{verification.vaultName}</b> · {verification.entryCount} {verification.entryCount === 1 ? 'login' : 'logins'} · format {verification.formatVersion}</p></div>
    </div>
    <div class="drill-restore-note"><strong>Verification is enough for a routine check.</strong><p>For a complete drill, restore this verified copy. Sesame first keeps a safety copy of the vault currently open, then locks so you can open the restored vault yourself.</p></div>
    {#if error}<p class="field-error" role="alert">{error}</p>{/if}
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={restoring} on:click={onClose}>Done</button><button type="button" class="danger-button" disabled={restoring} on:click={onRestore}>{restoring ? 'Restoring…' : 'Restore verified backup'}</button></div>
  {/if}
</ModalShell>

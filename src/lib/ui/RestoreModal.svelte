<script lang="ts">
  import Icon from '../Icon.svelte'
  import { describeBackupCompatibility } from '../backup-compatibility'
  import type { BackupSelection } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let restoreSelection: BackupSelection | null
  export let restoreConfirmed = false
  export let restoreSecret = ''
  export let restoringBackup = false
  export let replacesVault = true
  export let errorMessage = ''
  export let onClose: () => void
  export let onConfirm: () => void

  const focusSecret = (dialog: HTMLElement) => dialog.querySelector<HTMLInputElement>('#restore-secret')?.focus()

  $: formatCopy = restoreSelection ? describeBackupCompatibility(restoreSelection.compatibility, restoreSelection.formatVersion) : null
  $: replacementNote = restoreSelection?.compatibility === 'upgrade'
    ? 'Sesame opens the backup and upgrades a copy before replacing anything. The selected backup file is not changed. Your current vault is saved to the local backup folder first, and the restore names that safety copy.'
    : 'Sesame opens the backup before replacing anything. Your current vault is saved to the local backup folder first, and the restore names that safety copy.'
</script>

{#if restoreSelection && formatCopy}
  <ModalShell onClose={() => !restoringBackup && onClose()} labelledby="restore-heading" tone="restore" modalClass="restore-modal" initialFocus={focusSecret} ariaBusy={restoringBackup}>
      <button type="button" class="modal-close" disabled={restoringBackup} on:click={onClose} aria-label="Close restore">×</button>
      <span class="restore-icon"><Icon name="refresh" size={22} /></span>
      <h2 id="restore-heading">{formatCopy.canRestore ? (replacesVault ? 'Replace the current vault?' : 'Restore this backup?') : 'Sesame cannot restore this backup.'}</h2>
      <div class="restore-file"><Icon name="archive" size={17} /><div><strong>{restoreSelection.fileName}</strong><span>{formatCopy.label}</span></div></div>
      <p class="restore-format-detail">{formatCopy.detail}</p>
      {#if formatCopy.canRestore}
        <form on:submit|preventDefault={onConfirm}>
          <label for="restore-secret">This backup's master password or recovery kit</label>
          <input id="restore-secret" name="restore-secret" type="password" bind:value={restoreSecret} autocomplete="off" spellcheck="false" disabled={restoringBackup} />
          <p class="restore-warning">{replacesVault ? replacementNote : 'Sesame opens the backup with this first. Your vault is created from the backup only after it is proven readable.'}</p>
          {#if formatCopy.nextAction}<p class="restore-next-action">{formatCopy.nextAction}</p>{/if}
          {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
          {#if replacesVault}<label class="restore-confirm"><input name="confirm-vault-replacement" type="checkbox" bind:checked={restoreConfirmed} disabled={restoringBackup} /><span>I understand that the active vault will be replaced.</span></label>{/if}
          <div class="restore-actions"><button type="button" class="secondary-button" disabled={restoringBackup} on:click={onClose}>Cancel</button><button type="submit" class="danger-button" disabled={restoringBackup || !restoreSecret || (replacesVault && !restoreConfirmed)}>{restoringBackup ? 'Restoring…' : 'Restore backup'}</button></div>
        </form>
      {:else}
        <p class="restore-next-action" role="status">{formatCopy.nextAction}</p>
        <div class="restore-actions"><button type="button" class="secondary-button" on:click={onClose}>Close</button></div>
      {/if}
  </ModalShell>
{/if}

<style>
  .restore-format-detail { margin: var(--space-3) 0 0; color: var(--text-muted); font-size: var(--type-3); line-height: 1.55; }
  .restore-next-action { margin: var(--space-2) 0 0; color: var(--text); font-size: var(--type-3); line-height: 1.5; }
</style>

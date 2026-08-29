<script lang="ts">
  import Icon from '../Icon.svelte'
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
</script>

{#if restoreSelection}
  <ModalShell onClose={() => !restoringBackup && onClose()} labelledby="restore-heading" tone="restore" modalClass="restore-modal" initialFocus={focusSecret} ariaBusy={restoringBackup}>
      <button type="button" class="modal-close" disabled={restoringBackup} on:click={onClose} aria-label="Close restore">×</button>
      <span class="restore-icon"><Icon name="refresh" size={22} /></span>
      <p class="eyebrow">Restore encrypted backup</p>
      <h2 id="restore-heading">{replacesVault ? 'Replace the current vault?' : 'Restore this backup?'}</h2>
      <div class="restore-file"><Icon name="archive" size={17} /><div><strong>{restoreSelection.fileName}</strong><span>Sesame vault format {restoreSelection.formatVersion}</span></div></div>
      <form on:submit|preventDefault={onConfirm}>
        <label for="restore-secret">This backup's master password or recovery kit</label>
        <input id="restore-secret" type="password" bind:value={restoreSecret} autocomplete="off" spellcheck="false" disabled={restoringBackup} />
        <p class="restore-warning">{replacesVault ? 'Sesame opens the backup with this first. The current vault is replaced only after the backup is proven readable, and it is saved to the local backup folder beforehand.' : 'Sesame opens the backup with this first. Your vault is created from the backup only after it is proven readable.'}</p>
        {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
        {#if replacesVault}<label class="restore-confirm"><input type="checkbox" bind:checked={restoreConfirmed} disabled={restoringBackup} /><span>I understand that the active vault will be replaced.</span></label>{/if}
        <div class="restore-actions"><button type="button" class="secondary-button" disabled={restoringBackup} on:click={onClose}>Cancel</button><button type="submit" class="danger-button" disabled={restoringBackup || !restoreSecret || (replacesVault && !restoreConfirmed)}>{restoringBackup ? 'Restoring…' : 'Restore backup'}</button></div>
      </form>
  </ModalShell>
{/if}

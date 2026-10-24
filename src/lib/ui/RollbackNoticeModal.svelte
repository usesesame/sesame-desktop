<script lang="ts">
  import type { RollbackNotice } from '../vault'
  import ModalShell from './ModalShell.svelte'

  export let notice: RollbackNotice | null
  export let working = false
  export let errorMessage = ''
  export let onKeep: () => void
  export let onLock: () => void

  const focusKeep = (dialog: HTMLElement) => dialog.querySelector<HTMLButtonElement>('.primary-button')?.focus()
</script>

{#if notice}
  <ModalShell
    open={true}
    onClose={() => undefined}
    labelledby="rollback-heading"
    describedby="rollback-description"
    tone="cleanup-confirm"
    modalClass="cleanup-confirm-modal"
    initialFocus={focusKeep}
    ariaBusy={working}
  >
    <h2 id="rollback-heading">This vault is older than the last one you opened</h2>
    <p id="rollback-description">
      This vault is at revision {notice.foundRevision}, and this device last opened revision {notice.recordedRevision}. An older copy of the vault file may have been put back, or you may have restored a backup. If you restored on purpose, keep using it. If you did not, lock Sesame and check your backups before you change anything.
    </p>
    {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={onLock}>Lock Sesame</button>
      <button type="button" class="primary-button" disabled={working} on:click={onKeep}>{working ? 'Saving…' : 'Keep using this vault'}</button>
    </div>
  </ModalShell>
{/if}

<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let deleteVaultPassword = ''
  export let errorMessage = ''
  export let dataActionWorking = false
  export let onCancel: () => void
  export let onConfirm: () => void

  function cancel() {
    if (!dataActionWorking) onCancel()
  }
</script>

<ModalShell
  open={true}
  onClose={cancel}
  labelledby="delete-vault-heading"
  describedby="delete-vault-description"
  tone="data-controls"
  modalClass="delete-vault-modal"
  ariaBusy={dataActionWorking}
>
  <span class="confirm-icon danger"><Icon name="alert" size={20} /></span>
  <h2 id="delete-vault-heading">Remove the local vault?</h2>
  <p id="delete-vault-description">This removes the vault and the Sesame backups on this device, and it cannot be undone from Sesame. Enter your master password to confirm.</p>
  <form novalidate on:submit|preventDefault={onConfirm}>
    <label class="delete-vault-input" for="delete-vault-password">Master password</label>
    <input
      id="delete-vault-password"
      name="delete-vault-password"
      type="password"
      bind:value={deleteVaultPassword}
      autocomplete="current-password"
      spellcheck="false"
      disabled={dataActionWorking}
      aria-invalid={Boolean(errorMessage)}
      aria-describedby={errorMessage ? 'delete-vault-error' : undefined}
    />
    {#if errorMessage}<p id="delete-vault-error" class="form-error" role="alert">{errorMessage}</p>{/if}
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={dataActionWorking} on:click={cancel}>Cancel</button>
      <button type="submit" class="danger-button" disabled={!deleteVaultPassword || dataActionWorking}>{dataActionWorking ? 'Removing…' : 'Remove vault'}</button>
    </div>
  </form>
</ModalShell>

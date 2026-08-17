<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let deleteVaultText = ''
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
  <p id="delete-vault-description">This cannot be undone from Sesame. Type <code>DELETE</code> to confirm.</p>
  <label class="delete-vault-input">Confirmation<input bind:value={deleteVaultText} autocomplete="off" spellcheck="false" placeholder="DELETE" /></label>
  <div class="confirm-actions"><button type="button" class="secondary-button" disabled={dataActionWorking} on:click={cancel}>Cancel</button><button type="button" class="danger-button" disabled={deleteVaultText !== 'DELETE' || dataActionWorking} on:click={onConfirm}>{dataActionWorking ? 'Removing…' : 'Remove vault'}</button></div>
</ModalShell>

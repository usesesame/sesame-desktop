<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let deleteCandidate: { id: string; label: string } | null
  export let deleteWorking = false
  export let onCancel: () => void
  export let onConfirm: () => void

  function cancel() {
    if (!deleteWorking) onCancel()
  }
</script>

{#if deleteCandidate}
  <ModalShell
    open={true}
    onClose={cancel}
    labelledby="delete-identity-heading"
    describedby="delete-identity-description"
    tone="cleanup-confirm"
    modalClass="cleanup-confirm-modal"
    ariaBusy={deleteWorking}
  >
    <span class="confirm-icon danger"><Icon name="alert" size={20} /></span>
    <h2 id="delete-identity-heading">Delete {deleteCandidate.label}?</h2>
    <p id="delete-identity-description">This removes the name, email, phone, and address stored for this identity. It does not touch any saved login.</p>
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={deleteWorking} on:click={cancel}>Cancel</button><button type="button" class="danger-button" disabled={deleteWorking} on:click={onConfirm}>{deleteWorking ? 'Deleting…' : 'Delete identity'}</button></div>
  </ModalShell>
{/if}

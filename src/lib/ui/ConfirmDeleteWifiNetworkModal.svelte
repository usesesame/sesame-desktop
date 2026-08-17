<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let deleteCandidate: { id: string; title: string } | null
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
    labelledby="delete-wifi-network-heading"
    describedby="delete-wifi-network-description"
    tone="cleanup-confirm"
    modalClass="cleanup-confirm-modal"
    ariaBusy={deleteWorking}
  >
    <span class="confirm-icon danger"><Icon name="alert" size={20} /></span>
    <h2 id="delete-wifi-network-heading">Delete {deleteCandidate.title}?</h2>
    <p id="delete-wifi-network-description">This removes the network name and password stored for this network. It does not touch any saved login.</p>
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={deleteWorking} on:click={cancel}>Cancel</button><button type="button" class="danger-button" disabled={deleteWorking} on:click={onConfirm}>{deleteWorking ? 'Deleting…' : 'Delete network'}</button></div>
  </ModalShell>
{/if}

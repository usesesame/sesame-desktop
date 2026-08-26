<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let recordKind: string
  export let noun: string
  export let description: string
  export let deleteCandidate: { id: string; title: string } | null
  export let deleteWorking = false
  export let onCancel: () => void
  export let onConfirm: () => void

  $: headingId = `delete-${recordKind}-heading`
  $: descriptionId = `delete-${recordKind}-description`

  function cancel() {
    if (!deleteWorking) onCancel()
  }
</script>

{#if deleteCandidate}
  <ModalShell
    open={true}
    onClose={cancel}
    labelledby={headingId}
    describedby={descriptionId}
    tone="cleanup-confirm"
    modalClass="cleanup-confirm-modal"
    ariaBusy={deleteWorking}
  >
    <span class="confirm-icon danger"><Icon name="alert" size={20} /></span>
    <h2 id={headingId}>Delete {deleteCandidate.title}?</h2>
    <p id={descriptionId}>{description}</p>
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={deleteWorking} on:click={cancel}>Cancel</button><button type="button" class="danger-button" disabled={deleteWorking} on:click={onConfirm}>{deleteWorking ? 'Deleting…' : `Delete ${noun}`}</button></div>
  </ModalShell>
{/if}

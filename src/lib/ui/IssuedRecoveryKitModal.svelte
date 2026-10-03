<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let recoveryKit: string
  export let confirmed = false
  export let onDone: () => void

  function requestClose() {
    if (confirmed) onDone()
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="issued-recovery-kit-heading"
  describedby="issued-recovery-kit-description"
  modalClass="change-master-password-modal"
>
  <span class="confirm-icon"><Icon name="file-key" size={20} /></span>
  <h2 id="issued-recovery-kit-heading">Save your new recovery kit</h2>
  <p id="issued-recovery-kit-description">Your old recovery kit no longer opens this vault. Your master password still works. Write this kit down or store it outside Sesame.</p>
  <code class="recovery-code">{recoveryKit}</code>
  <label class="recovery-confirm"><input name="issued-recovery-kit-saved" type="checkbox" bind:checked={confirmed} /> <span>I saved this outside Sesame.</span></label>
  <div class="confirm-actions"><button type="button" class="primary-button" disabled={!confirmed} on:click={onDone}>Done</button></div>
</ModalShell>

<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let recoveryKit: string
  export let confirmed = false
  export let backupsPruned = false
  export let backupsRemaining: number | null = null
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
  <p id="issued-recovery-kit-description">Your old recovery kit no longer opens this vault, and the vault has a new encryption key. Your master password still works. PIN and Windows Hello unlock are off until you set them up again. Write this kit down or store it outside Sesame.</p>
  {#if !backupsPruned}
    <p class="backup-removal-warning" role="alert">Backups made before today still open with your old recovery kit. Delete them or keep them offline.</p>
  {:else if backupsRemaining === 0}
    <p class="backup-removal-note">Sesame removed its local backup copies in this vault folder. Backups you saved elsewhere still open with your old recovery kit. Delete them or keep them offline.</p>
  {:else if backupsRemaining === null}
    <p class="backup-removal-warning" role="alert">Sesame could not check whether it removed its local backup copies in this vault folder. Any copies that remain still open with your old recovery kit. Backups you saved elsewhere also still open with it.</p>
  {:else}
    <p class="backup-removal-warning" role="alert">Sesame could not remove {backupsRemaining} local backup {backupsRemaining === 1 ? 'copy' : 'copies'} in this vault folder. {backupsRemaining === 1 ? 'It still opens' : 'They still open'} with your old recovery kit. Backups you saved elsewhere also still open with it.</p>
  {/if}
  <code class="recovery-code">{recoveryKit}</code>
  <label class="recovery-confirm"><input name="issued-recovery-kit-saved" type="checkbox" bind:checked={confirmed} /> <span>I saved this outside Sesame.</span></label>
  <div class="confirm-actions"><button type="button" class="primary-button" disabled={!confirmed} on:click={onDone}>Done</button></div>
</ModalShell>

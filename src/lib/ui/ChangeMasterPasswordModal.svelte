<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let currentPassword = ''
  export let newPassword = ''
  export let confirmPassword = ''
  export let recoveryKit = ''
  export let recoveryConfirmed = false
  export let errorMessage = ''
  export let working = false
  export let onCancel: () => void
  export let onSave: () => void
  export let onDone: () => void

  $: passwordsMatch = newPassword === confirmPassword
  $: canSave = currentPassword.length > 0 && newPassword.length >= 12 && passwordsMatch
  $: showingRecoveryKit = Boolean(recoveryKit)

  function requestClose() {
    if (working) return
    if (showingRecoveryKit) {
      if (recoveryConfirmed) onDone()
      return
    }
    onCancel()
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="change-master-password-heading"
  describedby="change-master-password-description"
  modalClass="change-master-password-modal"
  ariaBusy={working}
>
  {#if showingRecoveryKit}
    <span class="confirm-icon"><Icon name="file-key" size={20} /></span>
    <p class="eyebrow">Recovery kit replaced</p>
    <h2 id="change-master-password-heading">Save this new kit.</h2>
    <p id="change-master-password-description">Your vault now uses a new encryption key. Your old recovery kit no longer opens it. PIN and Windows Hello unlock were turned off and can be enabled again after you save this new kit.</p>
    <code class="recovery-code">{recoveryKit}</code>
    <label class="recovery-confirm"><input name="replacement-recovery-kit-saved" type="checkbox" bind:checked={recoveryConfirmed} /> <span>I saved this outside Sesame.</span></label>
    <div class="confirm-actions"><button type="button" class="primary-button" disabled={!recoveryConfirmed} on:click={onDone}>Done</button></div>
  {:else}
    <span class="confirm-icon"><Icon name="key" size={20} /></span>
    <p class="eyebrow">Vault security</p>
    <h2 id="change-master-password-heading">Change master password</h2>
    <p id="change-master-password-description">Your vault stays local. This creates a new encryption key and recovery kit, and turns off PIN and Windows Hello unlock until you enable them again.</p>
    <form on:submit|preventDefault={onSave}>
      <label>Current master password<input name="current-master-password" type="password" bind:value={currentPassword} autocomplete="current-password" /></label>
      <label>New master password<input name="new-master-password" type="password" bind:value={newPassword} autocomplete="new-password" /></label>
      <label>Confirm new password<input name="confirm-new-master-password" type="password" bind:value={confirmPassword} autocomplete="new-password" /></label>
      {#if confirmPassword && !passwordsMatch}<p class="form-error" role="alert">Those new passwords do not match.</p>{:else if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
      <div class="confirm-actions"><button type="button" class="secondary-button" disabled={working} on:click={onCancel}>Cancel</button><button type="submit" class="primary-button" disabled={working || !canSave}>{working ? 'Updating…' : 'Change password'}</button></div>
    </form>
  {/if}
</ModalShell>

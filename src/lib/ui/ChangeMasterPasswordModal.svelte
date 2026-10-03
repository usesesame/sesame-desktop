<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let step: 'verify' | 'details' = 'verify'
  export let currentPassword = ''
  export let currentRecoveryKit = ''
  export let newPassword = ''
  export let confirmPassword = ''
  export let recoveryKit = ''
  export let backupsRemaining: number | null = null
  export let recoveryConfirmed = false
  export let errorMessage = ''
  export let working = false
  export let onCancel: () => void
  export let onVerify: () => void
  export let onUseRecoveryKit: () => void
  export let onBack: () => void
  export let onRequestNewKit: () => void = () => {}
  export let onSave: () => void
  export let onDone: () => void

  $: passwordsMatch = newPassword === confirmPassword
  $: canSave = currentRecoveryKit.trim().length > 0 && newPassword.length >= 12 && passwordsMatch
  $: usingRecoveryOnly = step === 'details' && currentPassword.length === 0
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
    <h2 id="change-master-password-heading">Save this new kit</h2>
    <p id="change-master-password-description">Your vault now uses a new encryption key. Your old recovery kit no longer opens it. Backups you exported or saved elsewhere still open with your old password. PIN and Windows Hello unlock were turned off and can be enabled again after you save this new kit.</p>
    {#if backupsRemaining === 0}
      <p class="backup-removal-note">Sesame removed its local backup copies in this vault folder.</p>
    {:else if backupsRemaining === null}
      <p class="backup-removal-warning" role="alert">Sesame could not check whether it removed its local backup copies in this vault folder. Any copies that remain still open with your old password.</p>
    {:else}
      <p class="backup-removal-warning" role="alert">Sesame could not remove {backupsRemaining} local backup {backupsRemaining === 1 ? 'copy' : 'copies'} in this vault folder. {backupsRemaining === 1 ? 'It still opens' : 'They still open'} with your old password. Remove {backupsRemaining === 1 ? 'it' : 'them'} before relying on the change.</p>
    {/if}
    <code class="recovery-code">{recoveryKit}</code>
    <label class="recovery-confirm"><input name="replacement-recovery-kit-saved" type="checkbox" bind:checked={recoveryConfirmed} /> <span>I saved this outside Sesame.</span></label>
    <div class="confirm-actions"><button type="button" class="primary-button" disabled={!recoveryConfirmed} on:click={onDone}>Done</button></div>
  {:else if step === 'verify'}
    <span class="confirm-icon"><Icon name="key" size={20} /></span>
    <h2 id="change-master-password-heading">Change master password</h2>
    <p id="change-master-password-description">Step 1 of 2. Enter your current master password. The next step asks for your recovery kit, so someone who learns your password cannot replace it and lock you out.</p>
    <form on:submit|preventDefault={onVerify}>
      <label>Current master password<input name="current-master-password" type="password" bind:value={currentPassword} autocomplete="current-password" /></label>
      {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
      <button type="button" class="text-button change-password-forgot" disabled={working} on:click={onUseRecoveryKit}>Forgot it? Use your recovery kit instead</button>
      <div class="confirm-actions"><button type="button" class="secondary-button" disabled={working} on:click={onCancel}>Cancel</button><button type="submit" class="primary-button" disabled={working || !currentPassword}>{working ? 'Checking…' : 'Continue'}</button></div>
    </form>
  {:else}
    <span class="confirm-icon"><Icon name="file-key" size={20} /></span>
    <h2 id="change-master-password-heading">{usingRecoveryOnly ? 'Reset master password' : 'Change master password'}</h2>
    <p id="change-master-password-description">{usingRecoveryOnly ? 'Enter your recovery kit and choose a new master password.' : 'Step 2 of 2. Enter your recovery kit and choose a new master password.'} This creates a new encryption key and recovery kit, and turns off PIN and Windows Hello unlock until you enable them again.</p>
    <form on:submit|preventDefault={onSave}>
      <label>Recovery kit<input name="current-recovery-kit" type="password" bind:value={currentRecoveryKit} autocomplete="off" spellcheck="false" autocapitalize="characters" /></label>
      <button type="button" class="text-button change-password-forgot" disabled={working} on:click={onRequestNewKit}>No recovery kit? Request a new one</button>
      <label>New master password<input name="new-master-password" type="password" bind:value={newPassword} autocomplete="new-password" /></label>
      <label>Confirm new password<input name="confirm-new-master-password" type="password" bind:value={confirmPassword} autocomplete="new-password" /></label>
      {#if confirmPassword && !passwordsMatch}<p class="form-error" role="alert">Those new passwords do not match.</p>{:else if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
      <div class="confirm-actions"><button type="button" class="secondary-button" disabled={working} on:click={onBack}>Back</button><button type="submit" class="primary-button" disabled={working || !canSave}>{working ? 'Updating…' : 'Change password'}</button></div>
    </form>
  {/if}
</ModalShell>

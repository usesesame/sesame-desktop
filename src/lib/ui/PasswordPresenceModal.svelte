<script lang="ts">
  import Icon from '../Icon.svelte'
  import { presenceCopy, type PresenceIntent } from '../presence-copy'
  import MasterPasswordField from './MasterPasswordField.svelte'
  import ModalShell from './ModalShell.svelte'

  export let presenceSecret = ''
  export let intent: PresenceIntent = 'reveal'
  export let errorMessage = ''
  export let pruneBackups = false
  export let onCancel: () => void
  export let onConfirm: () => void

  $: copy = presenceCopy[intent]
</script>

<ModalShell
  open={true}
  onClose={onCancel}
  labelledby="password-presence-heading"
  describedby="password-presence-description"
  tone="cleanup-confirm"
  modalClass="presence-modal"
>
  <span class="confirm-icon"><Icon name="key" size={20} /></span>
  <h2 id="password-presence-heading">{copy.heading}</h2>
  <p id="password-presence-description">{copy.description}</p>
  <form novalidate on:submit|preventDefault={onConfirm}>
    <MasterPasswordField id="presence-password" bind:value={presenceSecret} invalid={Boolean(errorMessage)} describedby={errorMessage ? 'presence-error' : undefined} />
    {#if intent === 'issue-kit'}
      <label class="recovery-confirm"><input name="prune-backups" type="checkbox" bind:checked={pruneBackups} /> <span>Also delete the backup copies Sesame saved in this vault folder.</span></label>
    {/if}
    {#if errorMessage}<p id="presence-error" class="form-error" role="alert">{errorMessage}</p>{/if}
    <div class="confirm-actions">
      <button type="button" class="secondary-button" on:click={onCancel}>Cancel</button>
      <button type="submit" class="primary-button" disabled={!presenceSecret}>{copy.action}</button>
    </div>
  </form>
</ModalShell>

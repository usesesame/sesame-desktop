<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let presenceSecret = ''
  export let errorMessage = ''
  export let onCancel: () => void
  export let onConfirm: () => void
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
  <h2 id="password-presence-heading">Show this password</h2>
  <p id="password-presence-description">Sesame asks for your master password again before it reveals a saved password.</p>
  <form novalidate on:submit|preventDefault={onConfirm}>
    <label class="delete-vault-input" for="presence-password">Master password</label>
    <input
      id="presence-password"
      name="presence-password"
      type="password"
      bind:value={presenceSecret}
      autocomplete="current-password"
      spellcheck="false"
      aria-invalid={Boolean(errorMessage)}
      aria-describedby={errorMessage ? 'presence-error' : undefined}
    />
    {#if errorMessage}<p id="presence-error" class="form-error" role="alert">{errorMessage}</p>{/if}
    <div class="confirm-actions">
      <button type="button" class="secondary-button" on:click={onCancel}>Cancel</button>
      <button type="submit" class="primary-button" disabled={!presenceSecret}>Show password</button>
    </div>
  </form>
</ModalShell>

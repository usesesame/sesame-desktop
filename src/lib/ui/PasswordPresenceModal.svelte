<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  type PresenceIntent = 'reveal' | 'copy' | 'autotype' | 'enable-icons' | 'request-kit' | 'issue-kit'

  export let presenceSecret = ''
  export let intent: PresenceIntent = 'reveal'
  export let errorMessage = ''
  export let pruneBackups = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const copyByIntent: Record<PresenceIntent, { heading: string; description: string; action: string }> = {
    reveal: {
      heading: 'Show this password',
      description: 'Sesame asks for your master password again before it reveals a saved password.',
      action: 'Show password',
    },
    copy: {
      heading: 'Copy this password',
      description: 'Sesame asks for your master password again before it copies a saved password. The password stays hidden.',
      action: 'Copy password',
    },
    autotype: {
      heading: 'Type this login',
      description: 'Sesame asks for your master password again before it types a saved login into another window. Typing starts after a short countdown so you can switch to the field.',
      action: 'Start typing',
    },
    'enable-icons': {
      heading: 'Turn on website icons',
      description: 'Sesame asks for your master password before it turns on website icon downloads for this device.',
      action: 'Turn on',
    },
    'request-kit': {
      heading: 'Request a new recovery kit',
      description: 'Enter your master password. The new kit is ready in 72 hours, measured with usesesame.app and github.com rather than this computer\'s clock. Sesame shows a warning on every unlock until then so a request you did not make can be cancelled.',
      action: 'Request kit',
    },
    'issue-kit': {
      heading: 'Get your new recovery kit',
      description: 'Enter your master password. Sesame gives the vault a new encryption key and a new kit. Your master password stays the same. The old kit stops opening this vault, and PIN and Windows Hello unlock turn off until you set them up again. Backups made before today still open with the old kit.',
      action: 'Get kit',
    },
  }

  $: copy = copyByIntent[intent]
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

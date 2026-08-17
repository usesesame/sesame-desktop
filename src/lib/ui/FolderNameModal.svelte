<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let name = ''
  export let title = 'New folder'
  export let description = 'Give this folder a short, useful name.'
  export let working = false
  export let onClose: () => void
  export let onSave: () => void

  const focusName = (dialog: HTMLElement) => {
    const input = dialog.querySelector<HTMLInputElement>('input')
    input?.focus()
    input?.select()
  }
</script>

<ModalShell onClose={() => !working && onClose()} labelledby="folder-name-heading" describedby="folder-name-description" modalClass="folder-name-modal" initialFocus={focusName} ariaBusy={working}>
  <form on:submit|preventDefault={onSave}>
    <span class="confirm-icon"><Icon name="folder" size={20} /></span>
    <h2 id="folder-name-heading">{title}</h2>
    <p id="folder-name-description">{description}</p>
    <label>Folder name<input bind:value={name} maxlength="100" required autocomplete="off" /></label>
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={working} on:click={onClose}>Cancel</button><button type="submit" class="primary-button" disabled={working || !name.trim()}>{working ? 'Saving…' : 'Save folder'}</button></div>
  </form>
</ModalShell>

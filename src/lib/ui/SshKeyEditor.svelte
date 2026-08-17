<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import type { SshKeyInput } from '../types'

  export let keyDraft: SshKeyInput
  export let editorTitle = 'Add a key'
  export let savingKey = false
  export let loadingKey = false
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingKey) return
    if (dirty) {
      confirmingDiscard = true
      return
    }
    onClose()
  }

  function discard() {
    confirmingDiscard = false
    dirty = false
    onClose()
  }

  function focusInitial() {
    titleInput?.focus()
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="ssh-key-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingKey || loadingKey}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{keyDraft.id ? 'Saved key' : 'New key'}</p><h2 id="ssh-key-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingKey} on:click={requestClose} aria-label="Close key editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this key appears in your list, e.g. "Deploy key"</span><input bind:this={titleInput} bind:value={keyDraft.title} required maxlength="160" placeholder="e.g. Deploy key" autocomplete="off" /></label>
    <label>Key type <span class="field-hint">Optional, e.g. ed25519</span><input bind:value={keyDraft.keyType} maxlength="32" autocomplete="off" /></label>
    <label>Private key<textarea bind:value={keyDraft.privateKey} rows="6" maxlength="16000" class="monospace-field"></textarea></label>
    <label>Public key<textarea bind:value={keyDraft.publicKey} rows="3" maxlength="4000" class="monospace-field"></textarea></label>
    <label>Passphrase<input bind:value={keyDraft.passphrase} maxlength="256" autocomplete="off" /></label>
    <label>Notes<textarea bind:value={keyDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input value={keyDraft.tags.join(', ')} on:input={(event) => (keyDraft = { ...keyDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. work, deploy" /></label>
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This key has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingKey} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingKey || loadingKey}>{savingKey ? 'Saving…' : 'Save key'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

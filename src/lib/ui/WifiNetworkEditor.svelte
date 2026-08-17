<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import type { WifiNetworkInput } from '../types'

  export let networkDraft: WifiNetworkInput
  export let editorTitle = 'Add a network'
  export let savingNetwork = false
  export let loadingNetwork = false
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingNetwork) return
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
  labelledby="wifi-network-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingNetwork || loadingNetwork}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{networkDraft.id ? 'Saved network' : 'New network'}</p><h2 id="wifi-network-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingNetwork} on:click={requestClose} aria-label="Close network editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this network appears in your list, e.g. "Home Wi-Fi"</span><input bind:this={titleInput} bind:value={networkDraft.title} required maxlength="160" placeholder="e.g. Home Wi-Fi" autocomplete="off" /></label>
    <label>Network name (SSID)<input bind:value={networkDraft.ssid} maxlength="64" autocomplete="off" /></label>
    <label>Password<input bind:value={networkDraft.password} maxlength="256" autocomplete="off" /></label>
    <label>Security type <span class="field-hint">Optional, e.g. WPA2</span><input bind:value={networkDraft.securityType} maxlength="32" autocomplete="off" /></label>
    <label>Notes<textarea bind:value={networkDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input value={networkDraft.tags.join(', ')} on:input={(event) => (networkDraft = { ...networkDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. home, travel" /></label>
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This network has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingNetwork} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingNetwork || loadingNetwork}>{savingNetwork ? 'Saving…' : 'Save network'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import type { SoftwareLicenseInput } from '../types'

  export let licenseDraft: SoftwareLicenseInput
  export let editorTitle = 'Add a licence'
  export let savingLicense = false
  export let loadingLicense = false
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingLicense) return
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
  labelledby="software-license-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingLicense || loadingLicense}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{licenseDraft.id ? 'Saved licence' : 'New licence'}</p><h2 id="software-license-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingLicense} on:click={requestClose} aria-label="Close licence editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this licence appears in your list, e.g. “Office suite”</span><input name="licence-title" bind:this={titleInput} bind:value={licenseDraft.title} required maxlength="160" placeholder="e.g. Office suite…" autocomplete="off" /></label>
    <label>Product<input name="licence-product" bind:value={licenseDraft.productName} maxlength="256" autocomplete="off" /></label>
    <label>Licence key<input name="licence-key" bind:value={licenseDraft.licenseKey} maxlength="512" autocomplete="off" class="monospace-field" spellcheck="false" /></label>
    <div class="editor-two-column">
      <label>Purchased from <span class="field-hint">Optional</span><input name="licence-vendor" bind:value={licenseDraft.purchasedFrom} maxlength="256" autocomplete="off" /></label>
      <label>Purchase date <span class="field-hint">Optional</span><input name="licence-purchase-date" bind:value={licenseDraft.purchaseDate} maxlength="32" autocomplete="off" /></label>
    </div>
    <label>Notes<textarea name="licence-notes" bind:value={licenseDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input name="licence-tags" value={licenseDraft.tags.join(', ')} on:input={(event) => (licenseDraft = { ...licenseDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. work, design…" /></label>
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This licence has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingLicense} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingLicense || loadingLicense}>{savingLicense ? 'Saving…' : 'Save licence'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

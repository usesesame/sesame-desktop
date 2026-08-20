<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import LegacyDataPanel from './LegacyDataPanel.svelte'
  import type { IdentityInput, LegacyField } from '../types'

  export let identityDraft: IdentityInput
  export let editorTitle = 'Add an identity'
  export let savingIdentity = false
  export let loadingIdentity = false
  export let legacyFields: LegacyField[] = []
  export let onSubmit: () => void
  export let onClose: () => void

  let labelInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingIdentity) return
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
    labelInput?.focus()
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="identity-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingIdentity || loadingIdentity}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{identityDraft.id ? 'Saved identity' : 'New identity'}</p><h2 id="identity-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingIdentity} on:click={requestClose} aria-label="Close identity editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Label <span class="field-hint">How this identity appears in your list, e.g. "Personal" or "Work"</span><input bind:this={labelInput} bind:value={identityDraft.label} required maxlength="160" placeholder="e.g. Personal" autocomplete="off" /></label>
    <label>Full name<input bind:value={identityDraft.fullName} maxlength="256" autocomplete="name" /></label>
    <div class="editor-two-column">
      <label>Email<input bind:value={identityDraft.email} maxlength="320" inputmode="email" autocomplete="email" /></label>
      <label>Phone<input bind:value={identityDraft.phone} maxlength="64" inputmode="tel" autocomplete="tel" /></label>
    </div>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input value={identityDraft.tags.join(', ')} on:input={(event) => (identityDraft.tags = event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean))} maxlength="500" autocomplete="off" placeholder="e.g. personal, travel" /></label>

    <section class="editor-section">
      <div><h3>Address</h3><p>Optional. Filled into signup forms that ask for one.</p></div>
      <label class="field-only-label">Address line 1<input bind:value={identityDraft.addressLine1} maxlength="256" autocomplete="address-line1" /></label>
      <label class="field-only-label">Address line 2 <span class="field-hint">Optional</span><input bind:value={identityDraft.addressLine2} maxlength="256" autocomplete="address-line2" /></label>
      <div class="editor-two-column">
        <label>City<input bind:value={identityDraft.city} maxlength="128" autocomplete="address-level2" /></label>
        <label>Region <span class="field-hint">State or province</span><input bind:value={identityDraft.region} maxlength="128" autocomplete="address-level1" /></label>
      </div>
      <div class="editor-two-column">
        <label>Postal code<input bind:value={identityDraft.postalCode} maxlength="32" autocomplete="postal-code" /></label>
        <label>Country<input bind:value={identityDraft.country} maxlength="128" autocomplete="country-name" /></label>
      </div>
    </section>
    <LegacyDataPanel fields={legacyFields} />
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This identity has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingIdentity} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingIdentity || loadingIdentity}>{savingIdentity ? 'Saving…' : 'Save identity'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

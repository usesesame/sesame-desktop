<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import LegacyDataPanel from './LegacyDataPanel.svelte'
  import type { CardInput, LegacyField } from '../types'

  export let cardDraft: CardInput
  export let editorTitle = 'Add a card'
  export let savingCard = false
  export let loadingCard = false
  export let legacyFields: LegacyField[] = []
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingCard) return
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
  labelledby="card-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingCard || loadingCard}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{cardDraft.id ? 'Saved card' : 'New card'}</p><h2 id="card-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingCard} on:click={requestClose} aria-label="Close card editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this card appears in your list, e.g. "Everyday card"</span><input bind:this={titleInput} bind:value={cardDraft.title} required maxlength="160" placeholder="e.g. Everyday card" autocomplete="off" /></label>
    <label>Cardholder name<input bind:value={cardDraft.cardholderName} maxlength="256" autocomplete="cc-name" /></label>
    <label>Card number<input bind:value={cardDraft.number} maxlength="32" inputmode="numeric" autocomplete="cc-number" /></label>
    <div class="editor-two-column">
      <label>Expiry month <span class="field-hint">MM</span><input bind:value={cardDraft.expiryMonth} maxlength="8" inputmode="numeric" autocomplete="cc-exp-month" /></label>
      <label>Expiry year <span class="field-hint">YYYY</span><input bind:value={cardDraft.expiryYear} maxlength="8" inputmode="numeric" autocomplete="cc-exp-year" /></label>
    </div>
    <div class="editor-two-column">
      <label>Security code<input bind:value={cardDraft.securityCode} maxlength="8" inputmode="numeric" autocomplete="cc-csc" /></label>
      <label>Network <span class="field-hint">Optional, e.g. Visa</span><input bind:value={cardDraft.brand} maxlength="64" autocomplete="cc-type" /></label>
    </div>
    <label>Notes<textarea bind:value={cardDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input value={cardDraft.tags.join(', ')} on:input={(event) => (cardDraft = { ...cardDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. personal, travel" /></label>
    <LegacyDataPanel fields={legacyFields} />
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This card has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingCard} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingCard || loadingCard}>{savingCard ? 'Saving…' : 'Save card'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

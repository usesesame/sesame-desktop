<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import LegacyDataPanel from './LegacyDataPanel.svelte'
  import type { LegacyField, SecureNoteInput } from '../types'

  export let noteDraft: SecureNoteInput
  export let editorTitle = 'Add a note'
  export let savingNote = false
  export let loadingNote = false
  export let legacyFields: LegacyField[] = []
  export let onDraftChange: (noteDraft: SecureNoteInput) => void
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function updateDraft(values: Partial<SecureNoteInput>) {
    noteDraft = { ...noteDraft, ...values }
    dirty = true
    onDraftChange(noteDraft)
  }

  function requestClose() {
    if (savingNote) return
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
  labelledby="secure-note-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingNote || loadingNote}
>
  <form on:submit|preventDefault={onSubmit}>
  <header class="editor-header">
    <div><p class="eyebrow">{noteDraft.id ? 'Saved note' : 'New note'}</p><h2 id="secure-note-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingNote} on:click={requestClose} aria-label="Close note editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Title <span class="field-hint">How this note appears in your list, e.g. “Home Wi-Fi”</span><input name="note-title" bind:this={titleInput} value={noteDraft.title} on:input={(event) => updateDraft({ title: event.currentTarget.value })} required maxlength="160" placeholder="e.g. Home Wi-Fi…" autocomplete="off" /></label>
    <label>Content<textarea name="note-content" value={noteDraft.content} on:input={(event) => updateDraft({ content: event.currentTarget.value })} rows="8" maxlength="20000" placeholder="What you want to keep…"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input name="note-tags" value={noteDraft.tags.join(', ')} on:input={(event) => updateDraft({ tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. home, travel…" /></label>
    <LegacyDataPanel fields={legacyFields} />
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This note has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingNote} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingNote || loadingNote}>{savingNote ? 'Saving…' : 'Save note'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import Icon from '../Icon.svelte'
  import type { CustomFieldEntry, CustomRecordInput } from '../types'

  export let recordDraft: CustomRecordInput
  export let editorTitle = 'Add a record'
  export let savingRecord = false
  export let loadingRecord = false
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  // Reassign, not mutate: a nested mutation does not propagate through bind:.
  function addField() {
    recordDraft = { ...recordDraft, fields: [...recordDraft.fields, { label: '', value: '', kind: 'text' }] }
    dirty = true
  }
  function removeField(index: number) {
    recordDraft = { ...recordDraft, fields: recordDraft.fields.filter((_, i) => i !== index) }
    dirty = true
  }
  function updateField(index: number, patch: Partial<CustomFieldEntry>) {
    recordDraft = { ...recordDraft, fields: recordDraft.fields.map((field, i) => (i === index ? { ...field, ...patch } : field)) }
    dirty = true
  }

  function requestClose() {
    if (savingRecord) return
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
  labelledby="custom-record-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingRecord || loadingRecord}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{recordDraft.id ? 'Saved record' : 'New record'}</p><h2 id="custom-record-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingRecord} on:click={requestClose} aria-label="Close record editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this record appears in your list</span><input bind:this={titleInput} bind:value={recordDraft.title} required maxlength="160" placeholder="e.g. Passport application" autocomplete="off" /></label>

    <section class="editor-section custom-fields-section">
      <div><h3>Fields</h3><p>Your own labelled values. A secret field is masked until you reveal it, the same as a password.</p></div>
      {#each recordDraft.fields as field, index (index)}
        <div class="custom-field-row">
          <input value={field.label} on:input={(event) => updateField(index, { label: event.currentTarget.value })} maxlength="160" placeholder="Label" autocomplete="off" class="custom-field-label" />
          <input
            value={field.value}
            on:input={(event) => updateField(index, { value: event.currentTarget.value })}
            maxlength="4000"
            placeholder="Value"
            autocomplete="off"
            type={field.kind === 'secret' ? 'password' : 'text'}
            class="custom-field-value"
          />
          <select value={field.kind} on:change={(event) => updateField(index, { kind: event.currentTarget.value })} class="custom-field-kind">
            <option value="text">Text</option>
            <option value="secret">Secret</option>
            <option value="date">Date</option>
          </select>
          <button type="button" class="icon-button" aria-label={`Remove field ${index + 1}`} title="Remove field" on:click={() => removeField(index)}><Icon name="trash" size={14} /></button>
        </div>
      {/each}
      <button type="button" class="secondary-button custom-field-add" on:click={addField}><Icon name="plus" size={14} /><span>Add field</span></button>
    </section>

    <label>Notes<textarea bind:value={recordDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input value={recordDraft.tags.join(', ')} on:input={(event) => (recordDraft = { ...recordDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. travel, family" /></label>
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This record has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingRecord} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingRecord || loadingRecord}>{savingRecord ? 'Saving…' : 'Save record'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

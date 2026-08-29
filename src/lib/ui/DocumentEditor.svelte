<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import Icon from '../Icon.svelte'
  import type { Attachment, DocumentMetadataInput } from '../types'

  export let documentDraft: DocumentMetadataInput
  export let editorTitle = 'Add a document'
  export let savingDocument = false
  export let loadingDocument = false
  export let attachments: Attachment[] = []
  export let uploadingAttachment = false
  export let removingAttachmentId: string | null = null
  export let attachmentError = ''
  export let onSubmit: () => void
  export let onClose: () => void
  export let onAddAttachment: (file: File) => void
  export let onRemoveAttachment: (attachmentId: string) => void

  let titleInput: HTMLInputElement
  let fileInput: HTMLInputElement

  const numberFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 })

  function formatBytes(bytes: number) {
    if (bytes < 1024) return `${numberFormat.format(bytes)} B`
    if (bytes < 1024 * 1024) return `${numberFormat.format(Math.max(0.1, bytes / 1024))} KB`
    return `${numberFormat.format(bytes / (1024 * 1024))} MB`
  }

  function handleFileChange(event: Event) {
    const file = (event.currentTarget as HTMLInputElement).files?.[0]
    if (file) onAddAttachment(file)
    ;(event.currentTarget as HTMLInputElement).value = ''
  }

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingDocument) return
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

  let armedRemovalId: string | null = null
  let armedRemovalTimer: ReturnType<typeof setTimeout> | null = null

  function removeAttachment(attachmentId: string) {
    if (armedRemovalId === attachmentId) {
      if (armedRemovalTimer) clearTimeout(armedRemovalTimer)
      armedRemovalId = null
      armedRemovalTimer = null
      onRemoveAttachment(attachmentId)
      return
    }
    armedRemovalId = attachmentId
    if (armedRemovalTimer) clearTimeout(armedRemovalTimer)
    armedRemovalTimer = setTimeout(() => {
      armedRemovalId = null
      armedRemovalTimer = null
    }, 4000)
  }

  function focusInitial() {
    titleInput?.focus()
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="document-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingDocument || loadingDocument}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{documentDraft.id ? 'Saved document' : 'New document'}</p><h2 id="document-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingDocument} on:click={requestClose} aria-label="Close document editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this document appears in your list, e.g. “Passport”</span><input name="document-title" bind:this={titleInput} bind:value={documentDraft.title} required maxlength="160" placeholder="e.g. Passport…" autocomplete="off" /></label>
    <label>Document type <span class="field-hint">Optional, e.g. Passport</span><input name="document-type" bind:value={documentDraft.documentType} maxlength="64" autocomplete="off" /></label>
    <label>Document number<input name="document-number" bind:value={documentDraft.documentNumber} maxlength="128" autocomplete="off" spellcheck="false" /></label>
    <label>Issuing authority <span class="field-hint">Optional</span><input name="document-issuer" bind:value={documentDraft.issuingAuthority} maxlength="256" autocomplete="off" /></label>
    <div class="editor-two-column">
      <label>Issue date <span class="field-hint">Optional</span><input name="document-issue-date" bind:value={documentDraft.issueDate} maxlength="32" autocomplete="off" /></label>
      <label>Expiry date <span class="field-hint">Optional</span><input name="document-expiry-date" bind:value={documentDraft.expiryDate} maxlength="32" autocomplete="off" /></label>
    </div>
    <label>Notes<textarea name="document-notes" bind:value={documentDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input name="document-tags" value={documentDraft.tags.join(', ')} on:input={(event) => (documentDraft = { ...documentDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. travel, family…" /></label>

    {#if documentDraft.id}
      <div class="document-attachments">
        <span class="document-attachments-label">Attachments <span class="field-hint">A photo or scan, up to 5 MB each</span></span>
        {#if attachments.length}
          <ul class="document-attachments-list">
            {#each attachments as attachment (attachment.id)}
              <li>
                <a class="document-attachment-download" href={`data:${attachment.contentType || 'application/octet-stream'};base64,${attachment.data}`} download={attachment.filename}>
                  <Icon name="file-key" size={15} />
                  <span class="document-attachment-name">{attachment.filename}</span>
                  <span class="document-attachment-size">{formatBytes(attachment.size)}</span>
                </a>
                <button
                  type="button"
                  class="icon-button"
                  class:confirm-armed={armedRemovalId === attachment.id}
                  aria-label={armedRemovalId === attachment.id ? `Select again to remove ${attachment.filename}` : `Remove ${attachment.filename}`}
                  title={armedRemovalId === attachment.id ? 'Select again to remove' : 'Remove attachment'}
                  disabled={removingAttachmentId === attachment.id}
                  on:click={() => removeAttachment(attachment.id)}
                >
                  <Icon name={removingAttachmentId === attachment.id ? 'refresh' : 'trash'} size={14} />
                </button>
              </li>
            {/each}
          </ul>
        {/if}
        {#if attachmentError}<p class="form-error" role="alert">{attachmentError}</p>{/if}
        <input bind:this={fileInput} type="file" class="sr-only" aria-label="Choose attachment file" on:change={handleFileChange} disabled={uploadingAttachment} />
        <button type="button" class="secondary-button" disabled={uploadingAttachment} on:click={() => fileInput.click()}>
          {uploadingAttachment ? 'Adding…' : 'Add attachment'}
        </button>
      </div>
    {/if}
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This document has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingDocument} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingDocument || loadingDocument}>{savingDocument ? 'Saving…' : 'Save document'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

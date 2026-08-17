<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { DocumentMetadataSummary } from '../types'

  export let documents: DocumentMetadataSummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="documents-view">
  {#if !documents.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md documents-empty-icon"><Icon name="id-card" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a document.</h2>
      <p>Store the details of an identity document once, and find them again when a form asks for them.</p>
      <button class="primary-button" on:click={onAdd}>Add a document</button>
    </section>
  {:else}
    <div class="documents-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add document</span></button>
    </div>
    <ul class="documents-list">
      {#each documents as document (document.id)}
        <li class="document-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${document.title}`} on:click={() => onEdit(document.id)}>
            <span class="entry-avatar"><Icon name="id-card" size={15} /></span>
            <strong>{document.title}</strong>
            {#if document.attachmentCount}
              <span class="document-attachment-badge" title={`${document.attachmentCount} ${document.attachmentCount === 1 ? 'attachment' : 'attachments'}`}>
                <Icon name="file-key" size={13} />{document.attachmentCount}
              </span>
            {/if}
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="document-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${document.title}`} title="Delete" on:click={() => onDelete(document.id, document.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { SecureNoteSummary } from '../types'

  export let notes: SecureNoteSummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="secure-notes-view">
  {#if !notes.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md secure-notes-empty-icon"><Icon name="note" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a note.</h2>
      <p>Store text you want to keep private and find again, separate from a login or an identity.</p>
      <button class="primary-button" on:click={onAdd}>Add a note</button>
    </section>
  {:else}
    <div class="secure-notes-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add note</span></button>
    </div>
    <ul class="secure-notes-list">
      {#each notes as note (note.id)}
        <li class="secure-note-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${note.title}`} on:click={() => onEdit(note.id)}>
            <span class="entry-avatar"><Icon name="note" size={15} /></span>
            <strong>{note.title}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="secure-note-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${note.title}`} title="Delete" on:click={() => onDelete(note.id, note.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

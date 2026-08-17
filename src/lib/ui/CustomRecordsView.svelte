<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { CustomRecordSummary } from '../types'

  export let records: CustomRecordSummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="custom-records-view">
  {#if !records.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md custom-records-empty-icon"><Icon name="custom" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a record.</h2>
      <p>Store a set of your own labelled fields for anything Sesame's other record types do not fit.</p>
      <button class="primary-button" on:click={onAdd}>Add a record</button>
    </section>
  {:else}
    <div class="custom-records-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add record</span></button>
    </div>
    <ul class="custom-records-list">
      {#each records as record (record.id)}
        <li class="custom-record-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${record.title}`} on:click={() => onEdit(record.id)}>
            <span class="entry-avatar"><Icon name="custom" size={15} /></span>
            <strong>{record.title}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="custom-record-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${record.title}`} title="Delete" on:click={() => onDelete(record.id, record.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { SoftwareLicenseSummary } from '../types'

  export let licenses: SoftwareLicenseSummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="software-licenses-view">
  {#if !licenses.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md software-licenses-empty-icon"><Icon name="license" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a licence.</h2>
      <p>Store a licence key once, and find it again the next time you reinstall or need to prove you own it.</p>
      <button class="primary-button" on:click={onAdd}>Add a licence</button>
    </section>
  {:else}
    <div class="software-licenses-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add licence</span></button>
    </div>
    <ul class="software-licenses-list">
      {#each licenses as license (license.id)}
        <li class="software-license-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${license.title}`} on:click={() => onEdit(license.id)}>
            <span class="entry-avatar"><Icon name="license" size={15} /></span>
            <strong>{license.title}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="software-license-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${license.title}`} title="Delete" on:click={() => onDelete(license.id, license.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

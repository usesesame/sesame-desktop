<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { IdentitySummary } from '../types'

  export let identities: IdentitySummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, label: string) => void
</script>

<section class="identities-view">
  {#if !identities.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md identities-empty-icon"><Icon name="user" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save an identity.</h2>
      <p>Store your details once, and use them to fill out a new account's signup form.</p>
      <button class="primary-button" on:click={onAdd}>Add an identity</button>
    </section>
  {:else}
    <div class="identities-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add identity</span></button>
    </div>
    <ul class="identities-list">
      {#each identities as identity (identity.id)}
        <li class="identity-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${identity.label}`} on:click={() => onEdit(identity.id)}>
            <span class="entry-avatar">{identity.label.slice(0, 1).toUpperCase() || '?'}</span>
            <strong>{identity.label}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="identity-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${identity.label}`} title="Delete" on:click={() => onDelete(identity.id, identity.label)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { SshKeySummary } from '../types'

  export let keys: SshKeySummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="ssh-keys-view">
  {#if !keys.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md ssh-keys-empty-icon"><Icon name="key" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a key.</h2>
      <p>Store a private key, public key, and passphrase once, and find them again when a server asks for one.</p>
      <button class="primary-button" on:click={onAdd}>Add a key</button>
    </section>
  {:else}
    <div class="ssh-keys-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add key</span></button>
    </div>
    <ul class="ssh-keys-list">
      {#each keys as key (key.id)}
        <li class="ssh-key-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${key.title}`} on:click={() => onEdit(key.id)}>
            <span class="entry-avatar"><Icon name="key" size={15} /></span>
            <strong>{key.title}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="ssh-key-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${key.title}`} title="Delete" on:click={() => onDelete(key.id, key.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { WifiNetworkSummary } from '../types'

  export let networks: WifiNetworkSummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="wifi-networks-view">
  {#if !networks.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md wifi-networks-empty-icon"><Icon name="wifi" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a network.</h2>
      <p>Store a network name and password once, and find it again the next time you need to join it.</p>
      <button class="primary-button" on:click={onAdd}>Add a network</button>
    </section>
  {:else}
    <div class="wifi-networks-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add network</span></button>
    </div>
    <ul class="wifi-networks-list">
      {#each networks as network (network.id)}
        <li class="wifi-network-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${network.title}`} on:click={() => onEdit(network.id)}>
            <span class="entry-avatar"><Icon name="wifi" size={15} /></span>
            <strong>{network.title}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="wifi-network-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${network.title}`} title="Delete" on:click={() => onDelete(network.id, network.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

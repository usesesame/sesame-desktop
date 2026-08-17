<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { CardSummary } from '../types'

  export let cards: CardSummary[] = []
  export let onAdd: () => void
  export let onEdit: (id: string) => void
  export let onDelete: (id: string, title: string) => void
</script>

<section class="cards-view">
  {#if !cards.length}
    <section class="item-empty-state">
      <span class="empty-brand size-md cards-empty-icon"><Icon name="card" size={32} /></span>
      <p class="eyebrow">Nothing saved yet</p>
      <h2>Save a card.</h2>
      <p>Store a card number, expiry, and security code once, and find it again when a form asks for one.</p>
      <button class="primary-button" on:click={onAdd}>Add a card</button>
    </section>
  {:else}
    <div class="cards-toolbar">
      <button type="button" class="import-button" on:click={onAdd}><Icon name="plus" size={14} /><span>Add card</span></button>
    </div>
    <ul class="cards-list">
      {#each cards as card (card.id)}
        <li class="card-row item-record-row">
          <button type="button" class="item-record-open" aria-label={`Edit ${card.title}`} on:click={() => onEdit(card.id)}>
            <span class="entry-avatar"><Icon name="card" size={15} /></span>
            <strong>{card.title}</strong>
            <Icon name="chevron-right" size={15} />
          </button>
          <div class="card-row-actions item-record-actions">
            <button type="button" class="icon-button" aria-label={`Delete ${card.title}`} title="Delete" on:click={() => onDelete(card.id, card.title)}><Icon name="trash" size={15} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

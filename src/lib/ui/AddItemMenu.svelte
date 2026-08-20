<script lang="ts">
  import { tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import { handleMenuItemKeydown, handleMenuTriggerKeydown, menuItemsIn } from '../menu-keys'
  import type { ItemKind } from '../types'
  import { ITEM_KINDS } from '../vault-items'

  export let open = false
  export let onToggle: (open?: boolean) => void
  export let onAdd: (kind: ItemKind) => void
  export let onImport: () => void

  let container: HTMLDivElement
  let trigger: HTMLButtonElement

  function close(returnFocus: boolean) {
    onToggle(false)
    if (returnFocus) trigger?.focus()
  }

  async function openWithFocus(index: number) {
    onToggle(true)
    await tick()
    menuItemsIn(container).at(index)?.focus()
  }

  function handleOutside(event: MouseEvent) {
    if (open && container && !container.contains(event.target as Node)) close(false)
  }
</script>

<svelte:window on:mousedown={handleOutside} />

<div class="add-item-menu" bind:this={container}>
  <button
    bind:this={trigger}
    type="button"
    class="add-login-button"
    aria-haspopup="menu"
    aria-expanded={open}
    aria-controls="add-item-options"
    on:click={() => onToggle()}
    on:keydown={(event) => handleMenuTriggerKeydown(event, (index) => void openWithFocus(index))}
  >
    <Icon name="plus" size={15} strokeWidth={2.2} /><span>Add</span>
  </button>
  {#if open}
    <div id="add-item-options" class="add-item-options" role="menu" aria-label="Add an item">
      {#each ITEM_KINDS as kind (kind.id)}
        <button type="button" role="menuitem" tabindex="-1" on:click={() => onAdd(kind.id)} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
          <Icon name={kind.icon} size={15} />{kind.addLabel}
        </button>
      {/each}
      <div class="add-item-footer">
        <button type="button" role="menuitem" tabindex="-1" on:click={() => { close(false); onImport() }} on:keydown={(event) => handleMenuItemKeydown(event, container, close)}>
          <Icon name="archive" size={15} />Import from another manager
        </button>
      </div>
    </div>
  {/if}
</div>

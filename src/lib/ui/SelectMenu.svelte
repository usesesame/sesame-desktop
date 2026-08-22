<script lang="ts">
  export let value: string
  export let options: Array<{ value: string; label: string }>
  export let onChange: (value: string) => void
  export let label: string
  export let id: string | undefined = undefined
  export let disabled = false
  export let triggerClass = ''

  let open = false
  let container: HTMLElement
  let trigger: HTMLButtonElement

  $: selectedLabel = options.find((option) => option.value === value)?.label ?? ''

  function optionButtons() {
    return [...(container?.querySelectorAll<HTMLButtonElement>('[role="option"]') ?? [])]
  }

  function close(returnFocus: boolean) {
    open = false
    if (returnFocus) trigger?.focus()
  }

  function choose(next: string) {
    onChange(next)
    close(true)
  }

  function handleOutside(event: MouseEvent) {
    if (open && container && !container.contains(event.target as Node)) close(false)
  }

  function handleTriggerKeydown(event: KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      open = true
      const buttons = optionButtons()
      const selected = buttons.find((button) => button.getAttribute('aria-selected') === 'true')
      ;(selected ?? buttons[0])?.focus()
    }
  }

  function handleOptionKeydown(event: KeyboardEvent) {
    const buttons = optionButtons()
    const current = Math.max(0, buttons.indexOf(event.currentTarget as HTMLButtonElement))
    let next: number | null = null
    if (event.key === 'ArrowDown') next = (current + 1) % buttons.length
    if (event.key === 'ArrowUp') next = (current - 1 + buttons.length) % buttons.length
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = buttons.length - 1
    if (next !== null) {
      event.preventDefault()
      buttons[next]?.focus()
      return
    }
    if (event.key === 'Escape') {
      event.preventDefault()
      close(true)
      return
    }
    if (event.key === 'Tab') close(false)
  }
</script>

<svelte:window on:mousedown={handleOutside} />

<div class="sort-control" bind:this={container}>
  <button
    bind:this={trigger}
    {id}
    type="button"
    class="sort-select-trigger {triggerClass}"
    aria-haspopup="listbox"
    aria-expanded={open}
    aria-label={label}
    {disabled}
    on:click={() => (open = !open)}
    on:keydown={handleTriggerKeydown}
  >
    <span>{selectedLabel}</span>
    <svg viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 4.5 6 8l3.5-3.5" /></svg>
  </button>
  {#if open}
    <div class="sort-menu" role="listbox" aria-label={label}>
      {#each options as option (option.value)}
        <button
          type="button"
          class:selected={option.value === value}
          role="option"
          aria-selected={option.value === value}
          tabindex="-1"
          on:click={() => choose(option.value)}
          on:keydown={handleOptionKeydown}
        >{option.label}</button>
      {/each}
    </div>
  {/if}
</div>

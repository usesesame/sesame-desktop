<script lang="ts">
  import Icon from '../Icon.svelte'

  export let notice: { title: string; message: string } | null = null
  export let errorMessage = ''
  export let onDismissNotice: () => void
  export let onDismissError: () => void
  export let onHold: () => void = () => {}
  export let onResume: () => void = () => {}

  let hovered = false
  let focused = false

  $: if (!notice) {
    hovered = false
    focused = false
  }

  function setPointer(value: boolean) {
    setPresence(value, focused)
    hovered = value
  }

  function setFocus(value: boolean) {
    setPresence(hovered, value)
    focused = value
  }

  function setPresence(nextHovered: boolean, nextFocused: boolean) {
    const wasHeld = hovered || focused
    const isHeld = nextHovered || nextFocused
    if (isHeld && !wasHeld) onHold()
    else if (!isHeld && wasHeld) onResume()
  }
</script>

{#if notice}
  <div class="toast" role="status" aria-live="polite" aria-atomic="true" on:mouseenter={() => setPointer(true)} on:mouseleave={() => setPointer(false)} on:focusin={() => setFocus(true)} on:focusout={() => setFocus(false)}>
    <span class="toast-icon" aria-hidden="true"><Icon name="check" size={15} strokeWidth={2.2} /></span>
    <div><strong>{notice.title}</strong><p>{notice.message}</p></div>
    <button type="button" aria-label="Dismiss notification" on:click={onDismissNotice}>×</button>
    <span class="toast-timer" aria-hidden="true"></span>
  </div>
{/if}
{#if errorMessage}<div class="alert" role="alert" aria-atomic="true"><span class="toast-icon" aria-hidden="true"><Icon name="alert" size={15} strokeWidth={2} /></span><p>{errorMessage}</p><button type="button" aria-label="Dismiss error" on:click={onDismissError}>×</button></div>{/if}

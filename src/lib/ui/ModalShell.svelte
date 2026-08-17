<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte'

  export let open = true
  export let onClose: () => void
  export let labelledby = ''
  export let describedby = ''
  export let tone = ''
  export let modalClass = ''
  export let initialFocus: ((dialog: HTMLElement) => void) | null = null
  export let ariaBusy: boolean | undefined = undefined

  let dialog: HTMLDivElement
  let returnFocus: HTMLElement | null = null

  const focusableSelector = [
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'textarea:not([disabled])',
    'select:not([disabled])',
    'a[href]',
    '[contenteditable="true"]',
    '[tabindex]:not([tabindex="-1"])',
  ].join(',')

  function focusableElements() {
    if (!dialog) return []
    return [...dialog.querySelectorAll<HTMLElement>(focusableSelector)].filter((element) => {
      if (element.closest('[hidden], [inert], [aria-hidden="true"]')) return false
      return element.getClientRects().length > 0
    })
  }

  function isTopmostModal() {
    const shells = [...document.querySelectorAll<HTMLElement>('[data-modal-shell]')]
    return shells[shells.length - 1]?.contains(dialog) ?? false
  }

  async function focusModal() {
    await tick()
    if (!open || !dialog) return
    if (initialFocus) {
      initialFocus(dialog)
      if (dialog.contains(document.activeElement)) return
    }
    const target = focusableElements()[0] ?? dialog
    target.focus({ preventScroll: true })
  }

  function restoreFocus() {
    const target = returnFocus
    returnFocus = null
    if (!target?.isConnected) return
    queueMicrotask(() => target.focus({ preventScroll: true }))
  }

  function closeOnBackdrop(event: MouseEvent) {
    if (event.target === event.currentTarget && isTopmostModal()) onClose()
  }

  function handleKeydown(event: KeyboardEvent) {
    if (!open || !dialog || !isTopmostModal()) return
    if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      onClose()
      return
    }
    if (event.key !== 'Tab') return
    const focusable = focusableElements()
    if (!focusable.length) {
      event.preventDefault()
      dialog.focus({ preventScroll: true })
      return
    }
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    const active = document.activeElement
    if (!dialog.contains(active)) {
      event.preventDefault()
      ;(event.shiftKey ? last : first).focus({ preventScroll: true })
    } else if (event.shiftKey && active === first) {
      event.preventDefault()
      last.focus({ preventScroll: true })
    } else if (!event.shiftKey && active === last) {
      event.preventDefault()
      first.focus({ preventScroll: true })
    }
  }

  onMount(() => {
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    void focusModal()
  })

  onDestroy(restoreFocus)
</script>

<svelte:window on:keydown={handleKeydown} />

{#if open}
  <div class="modal-backdrop{tone ? ` ${tone}-backdrop` : ''}" data-modal-shell role="presentation" on:click={closeOnBackdrop}>
    <div bind:this={dialog} class="modal{modalClass ? ` ${modalClass}` : ''}" role="dialog" aria-modal="true" aria-labelledby={labelledby} aria-describedby={describedby || undefined} aria-busy={ariaBusy} tabindex="-1">
      <slot />
    </div>
  </div>
{/if}

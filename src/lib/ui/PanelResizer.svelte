<script lang="ts">
  export let label: string
  export let value: number
  export let min: number
  export let max: number
  export let fallback: number
  export let direction: 1 | -1 = 1
  export let onResize: (next: number) => void
  export let onCommit: () => void

  const STEP = 16
  let dragging = false
  let startX = 0
  let startValue = 0

  const clamp = (next: number) => Math.min(max, Math.max(min, Math.round(next)))

  function onPointerDown(event: PointerEvent) {
    if (event.button !== 0) return
    dragging = true
    startX = event.clientX
    startValue = value
    ;(event.currentTarget as HTMLElement).setPointerCapture(event.pointerId)
    event.preventDefault()
  }

  function onPointerMove(event: PointerEvent) {
    if (!dragging) return
    onResize(clamp(startValue + (event.clientX - startX) * direction))
  }

  function endDrag(event: PointerEvent) {
    if (!dragging) return
    dragging = false
    ;(event.currentTarget as HTMLElement).releasePointerCapture?.(event.pointerId)
    onCommit()
  }

  function onKeydown(event: KeyboardEvent) {
    const step = event.shiftKey ? STEP * 4 : STEP
    let next: number | null = null
    if (event.key === 'ArrowLeft') next = clamp(value - step * direction)
    else if (event.key === 'ArrowRight') next = clamp(value + step * direction)
    else if (event.key === 'Home') next = direction === 1 ? min : max
    else if (event.key === 'End') next = direction === 1 ? max : min
    else if (event.key === 'Enter') next = fallback
    if (next === null) return
    event.preventDefault()
    onResize(next)
    onCommit()
  }

  function reset() {
    onResize(fallback)
    onCommit()
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
  class="panel-resizer"
  class:dragging
  role="separator"
  aria-orientation="vertical"
  aria-label={label}
  aria-valuenow={value}
  aria-valuemin={min}
  aria-valuemax={max}
  tabindex="0"
  on:pointerdown={onPointerDown}
  on:pointermove={onPointerMove}
  on:pointerup={endDrag}
  on:pointercancel={endDrag}
  on:dblclick={reset}
  on:keydown={onKeydown}
></div>

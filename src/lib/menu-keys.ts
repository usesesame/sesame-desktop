export function menuItemsIn(container: HTMLElement | undefined): HTMLButtonElement[] {
  return [...(container?.querySelectorAll<HTMLButtonElement>('[role="menuitem"], [role="menuitemradio"]') ?? [])]
}

export function handleMenuTriggerKeydown(event: KeyboardEvent, open: (index: number) => void): boolean {
  if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
    event.preventDefault()
    open(0)
    return true
  }
  if (event.key === 'ArrowUp') {
    event.preventDefault()
    open(-1)
    return true
  }
  return false
}

export function handleMenuItemKeydown(
  event: KeyboardEvent,
  container: HTMLElement | undefined,
  close: (returnFocus: boolean) => void,
): void {
  const items = menuItemsIn(container)
  const current = Math.max(0, items.indexOf(event.currentTarget as HTMLButtonElement))
  let next: number | null = null
  if (event.key === 'ArrowDown') next = (current + 1) % items.length
  if (event.key === 'ArrowUp') next = (current - 1 + items.length) % items.length
  if (event.key === 'Home') next = 0
  if (event.key === 'End') next = items.length - 1
  if (next !== null) {
    event.preventDefault()
    items[next]?.focus()
    return
  }
  if (event.key === 'Escape') {
    event.preventDefault()
    close(true)
    return
  }
  if (event.key === 'Tab') close(false)
}

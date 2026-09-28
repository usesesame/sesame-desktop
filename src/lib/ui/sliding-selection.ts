export function slidingSelection(node: HTMLElement) {
  const marker = document.createElement('span')
  marker.className = 'segment-marker'
  marker.setAttribute('aria-hidden', 'true')
  node.prepend(marker)

  function place() {
    const active = node.querySelector<HTMLElement>('button.active')
    if (!active) {
      delete marker.dataset.placed
      return
    }
    marker.style.width = `${active.offsetWidth}px`
    marker.style.height = `${active.offsetHeight}px`
    marker.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`
    if (!marker.dataset.placed) requestAnimationFrame(() => (marker.dataset.placed = 'true'))
  }

  place()
  const selection = new MutationObserver(place)
  selection.observe(node, { attributes: true, attributeFilter: ['class'], subtree: true })
  const resize = new ResizeObserver(place)
  resize.observe(node)
  return {
    destroy() {
      selection.disconnect()
      resize.disconnect()
      marker.remove()
    },
  }
}

export function disableDefaultContextMenu(target: Document = document): () => void {
  const preventDefaultMenu = (event: MouseEvent) => event.preventDefault()
  target.addEventListener('contextmenu', preventDefaultMenu)
  return () => target.removeEventListener('contextmenu', preventDefaultMenu)
}

<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import type { Folder, VaultEntry } from '../types'

  export let entry: VaultEntry
  export let x = 0
  export let y = 0
  export let folders: Folder[] = []
  export let working = false
  export let onClose: () => void
  export let onOpen: () => void
  export let onCopyUsername: () => void
  export let onCopyEmail: () => void
  export let onCopyPassword: () => void
  export let onEdit: () => void
  export let onDelete: () => void
  export let onMove: (folderId?: string) => void
  export let onNewFolder: () => void
  export let onToggleFavourite: () => void

  let menu: HTMLDivElement
  let left = x
  let top = y
  let foldersOpen = false
  let returnFocus: HTMLElement | null = null
  let folderTrigger: HTMLButtonElement

  function directMenuItems(container: HTMLElement) {
    return [...container.children].filter((element): element is HTMLButtonElement => {
      return element instanceof HTMLButtonElement && element.getAttribute('role')?.startsWith('menuitem') === true && !element.disabled
    })
  }

  function activeMenu() {
    const active = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const container = active?.closest<HTMLElement>('[role="menu"]')
    return container && menu.contains(container) ? container : menu
  }

  async function openFolderMenu() {
    foldersOpen = true
    await tick()
    const submenu = menu.querySelector<HTMLElement>('#entry-folder-submenu')
    if (submenu) directMenuItems(submenu)[0]?.focus()
  }

  async function closeFolderMenu() {
    foldersOpen = false
    await tick()
    folderTrigger?.focus()
  }

  onMount(async () => {
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    await tick()
    const bounds = menu.getBoundingClientRect()
    left = Math.max(8, Math.min(x, window.innerWidth - bounds.width - 8))
    top = Math.max(8, Math.min(y, window.innerHeight - bounds.height - 8))
    directMenuItems(menu)[0]?.focus()
  })

  onDestroy(() => {
    const target = returnFocus
    if (target?.isConnected) queueMicrotask(() => target.focus({ preventScroll: true }))
  })

  function outside(event: MouseEvent) {
    if (menu && !menu.contains(event.target as Node)) onClose()
  }

  function keydown(event: KeyboardEvent) {
    if (!menu) return
    const active = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const inFolderMenu = Boolean(active?.closest('#entry-folder-submenu'))
    if (event.key === 'Escape') {
      event.preventDefault()
      if (foldersOpen && inFolderMenu) {
        event.stopPropagation()
        void closeFolderMenu()
        return
      }
      onClose()
      return
    }
    if (event.key === 'Tab') {
      onClose()
      return
    }
    if (event.key === 'ArrowLeft' && inFolderMenu) {
      event.preventDefault()
      void closeFolderMenu()
      return
    }
    if (event.key === 'ArrowRight' && active === folderTrigger) {
      event.preventDefault()
      void openFolderMenu()
      return
    }
    const items = directMenuItems(activeMenu())
    const current = Math.max(0, items.indexOf(document.activeElement as HTMLButtonElement))
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      const direction = event.key === 'ArrowDown' ? 1 : -1
      items[(current + direction + items.length) % items.length]?.focus()
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault()
      items[event.key === 'Home' ? 0 : items.length - 1]?.focus()
    } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const query = event.key.toLocaleLowerCase()
      const ordered = [...items.slice(current + 1), ...items.slice(0, current + 1)]
      const match = ordered.find((item) => item.textContent?.trim().toLocaleLowerCase().startsWith(query))
      if (match) {
        event.preventDefault()
        match.focus()
      }
    }
  }
</script>

<svelte:window on:mousedown={outside} on:keydown={keydown} />

<div bind:this={menu} class="entry-context-menu" role="menu" aria-label={`Actions for ${entry.title}`} style={`left:${left}px;top:${top}px`}>
  <div class="context-menu-heading"><span class="entry-avatar">{entry.initials}</span><span><strong>{entry.title}</strong><small>{entry.site}</small></span></div>
  <button type="button" role="menuitem" disabled={entry.issueKinds.includes('url') || working} on:click={onOpen}><Icon name="external" size={15} /><span>Open site</span></button>
  <button type="button" role="menuitem" disabled={working} on:click={onCopyUsername}><Icon name="user" size={15} /><span>Copy username</span></button>
  <button type="button" role="menuitem" disabled={working} on:click={onCopyEmail}><Icon name="mail" size={15} /><span>Copy email</span></button>
  <button type="button" role="menuitem" disabled={working} on:click={onCopyPassword}><Icon name="key" size={15} /><span>Copy password</span></button>
  <button type="button" role="menuitemcheckbox" aria-checked={entry.favourite} disabled={working} on:click={onToggleFavourite}><span class="context-favourite" aria-hidden="true">{entry.favourite ? '★' : '☆'}</span><span>{entry.favourite ? 'Remove from favourites' : 'Add to favourites'}</span></button>
  <div class="context-menu-separator" role="separator"></div>
  <button bind:this={folderTrigger} type="button" role="menuitem" aria-haspopup="menu" aria-controls="entry-folder-submenu" aria-expanded={foldersOpen} disabled={working} on:click={() => (foldersOpen = !foldersOpen)}><Icon name="folder" size={15} /><span>Move to folder</span><Icon name="chevron-right" size={14} /></button>
  {#if foldersOpen}
    <div id="entry-folder-submenu" class="folder-menu-items" role="menu" aria-label="Folders">
      {#each folders as folder (folder.id)}
        <button type="button" role="menuitemradio" aria-checked={entry.folderId === folder.id} class:current={entry.folderId === folder.id} disabled={working} on:click={() => entry.folderId === folder.id ? onClose() : onMove(folder.id)}><span class="folder-menu-indent"></span><span>{folder.name}</span>{#if entry.folderId === folder.id}<Icon name="check" size={13} />{/if}</button>
      {/each}
      {#if entry.folderId}<button type="button" role="menuitem" disabled={working} on:click={() => onMove(undefined)}><span class="folder-menu-indent"></span><span>Move to Unfiled</span></button>{/if}
      <button type="button" role="menuitem" disabled={working} on:click={onNewFolder}><span class="folder-menu-indent"></span><span>New folder…</span><Icon name="plus" size={13} /></button>
    </div>
  {/if}
  <div class="context-menu-separator" role="separator"></div>
  <button type="button" role="menuitem" disabled={working} on:click={onEdit}><Icon name="pencil" size={15} /><span>Edit login</span></button>
  <button type="button" role="menuitem" class="danger" disabled={working} on:click={onDelete}><Icon name="trash" size={15} /><span>Delete login</span></button>
</div>

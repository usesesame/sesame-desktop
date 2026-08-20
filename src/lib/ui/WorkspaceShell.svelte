<script lang="ts">
  import { useAppStores } from '../stores/app-stores'
  import type { View } from '../types'
  import Icon from '../Icon.svelte'
  import Sidebar from './Sidebar.svelte'
  import Toast from './Toast.svelte'

  export let navigation: Array<{ id: View; label: string; icon: string }>
  export let preview = false
  export let duplicateReviewOpen = false
  export let refreshing = false
  export let notice: { title: string; message: string } | null = null
  export let errorMessage = ''
  export let onNavigate: (view: View) => void
  export let onLock: () => void
  export let onCycleTheme: () => void
  export let onRefresh: () => void
  export let onDismissNotice: () => void
  export let onDismissError: () => void
  export let onNewLogin: () => void = () => {}
  export let onCopyPassword: () => void = () => {}
  export let onCopyUsername: () => void = () => {}
  export let onEditSelected: () => void = () => {}
  export let onOpenSearch: () => void = () => {}

  const { selection, settings, vault } = useAppStores()

  function handleShortcut(event: KeyboardEvent) {
    const target = event.target as HTMLElement | null
    if (target?.closest('[role="dialog"]')) return
    const typing = target?.matches('input, textarea, select, [contenteditable="true"]')
    // Without the activeView guard, Ctrl+C anywhere would overwrite the clipboard with the last open login.
    const key = event.key.toLowerCase()
    const chord = (event.ctrlKey || event.metaKey) && !event.altKey
    if (chord && key === 'l') {
      event.preventDefault()
      onLock()
      return
    }
    if (typing) return
    if (!$vault.status.unlocked) return
    if (!chord && !event.altKey && event.key === '/') {
      event.preventDefault()
      onOpenSearch()
      return
    }
    if (!chord) return
    if (key === 'k') {
      event.preventDefault()
      onOpenSearch()
    } else if (key === 'n') {
      event.preventDefault()
      onNewLogin()
    } else if (key === 'c' && $selection.activeView === 'vault' && $vault.loginCard) {
      event.preventDefault()
      if (event.shiftKey) onCopyUsername()
      else onCopyPassword()
    } else if (key === 'e' && $selection.activeView === 'vault' && $vault.loginCard) {
      event.preventDefault()
      onEditSelected()
    }
  }
  const viewTitles: Record<View, string> = {
    vault: 'Your vault',
    authenticator: 'Authenticator',
    security: 'Checkup',
    tools: 'Password tools',
    trash: 'Trash',
    history: 'History',
    backups: 'Backups',
    settings: 'Settings',
  }
  $: title = $selection.activeView === 'security' && duplicateReviewOpen ? 'Duplicate review' : viewTitles[$selection.activeView]
  const themeIcon = { auto: 'monitor', light: 'sun', dark: 'moon' } as const
</script>

<svelte:window on:keydown={handleShortcut} />

<main class="app-shell">
  <Sidebar {navigation} activeView={$selection.activeView} {preview} autoLockMinutes={$settings.autoLockMinutes} onNavigate={(id) => onNavigate(id as View)} {onLock} />

  <section class="workspace" class:vault-workspace={$selection.activeView === 'vault'} class:cleanup-workspace={$selection.activeView === 'security' && duplicateReviewOpen} aria-labelledby="workspace-heading">
    <header class="topbar">
      <div><h1 id="workspace-heading">{title}</h1></div>
      <div class="topbar-actions">
        <button type="button" class="icon-button" aria-label="Change theme (currently {$settings.theme})" title="Theme: {$settings.theme}" on:click={onCycleTheme}><Icon name={themeIcon[$settings.theme]} size={15} /></button>
        <button type="button" class="icon-button" aria-label={refreshing ? 'Refreshing vault view' : 'Refresh vault view'} title={refreshing ? 'Refreshing…' : 'Refresh'} aria-busy={refreshing} disabled={refreshing} on:click={onRefresh}>{#if refreshing}<span class="refresh-spinner" aria-hidden="true"></span>{:else}<Icon name="refresh" size={14} />{/if}</button>
      </div>
    </header>

    <p class="sr-only" role="status" aria-live="polite" aria-atomic="true">Current section: {title}</p>

    <Toast {notice} {errorMessage} {onDismissNotice} {onDismissError} />
    <slot />
  </section>
</main>

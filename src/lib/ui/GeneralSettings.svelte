<script lang="ts">
  import { describeFreshness } from '../update-freshness-text'
  import { slidingSelection } from './sliding-selection'
  import Icon from '../Icon.svelte'
  import { appVersion } from '../app-meta'
  import { SHORTCUTS } from '../shortcuts'
  import { platformCapabilities } from '../platform'
  import type { DesktopUpdateProgress, DesktopUpdateStatus, Theme } from '../types'

  export let theme: Theme = 'auto'
  export let onSetTheme: (value: Theme) => void
  export let siteIconsEnabled = false
  export let siteIconsWorking = false
  export let onSetSiteIconsEnabled: (enabled: boolean) => void
  export let websiteIconCacheWorking = false
  export let websiteIconCacheEntryCount = 0
  export let websiteIconCacheIconCount = 0
  export let websiteIconCacheSizeBytes = 0
  export let onClearWebsiteIconCache: () => void
  export let keepInTray = true
  export let trayWorking = false
  export let onToggleTray: () => void
  export let autostartEnabled = false
  export let autostartWorking = false
  export let onToggleAutostart: () => void
  export let quickAccessShortcut = 'Ctrl+Alt+S'
  export let quickAccessShortcutWorking = false
  export let onUpdateQuickAccessShortcut: (accelerator: string) => void
  export let desktopUpdate: DesktopUpdateStatus = { available: false }
  export let updateWorking = false
  export let updateProgress: DesktopUpdateProgress | null = null
  export let onCheckForUpdate: () => void
  export let onInstallUpdate: () => void

  $: freshnessNote = describeFreshness(desktopUpdate)
  let recordingShortcut = false

  function formatAccelerator(value: string): string {
    return value.split('+').join(' + ')
  }

  function startRecordingShortcut() {
    recordingShortcut = true
  }

  function cancelRecordingShortcut() {
    recordingShortcut = false
  }

  const NAMED_CODE_TOKENS: Record<string, string> = {
    Space: 'Space', Tab: 'Tab', Enter: 'Return', Backspace: 'Backspace', Delete: 'Delete',
    Minus: '-', Equal: '=', Comma: ',', Period: '.', Slash: '/', Semicolon: ';', Quote: "'",
    BracketLeft: '[', BracketRight: ']', Backslash: '\\', Backquote: '`',
  }

  function tokenForCode(code: string): string | null {
    if (code.startsWith('Key')) return code.slice(3)
    if (code.startsWith('Digit')) return code.slice(5)
    if (code.startsWith('Numpad')) return `Num${code.slice(6)}`
    if (code.startsWith('Arrow')) return code
    if (/^F\d{1,2}$/.test(code)) return code
    return NAMED_CODE_TOKENS[code] ?? null
  }

  // Meta is left out: its token name in the shortcut crate is not confirmed.
  function handleShortcutKeydown(event: KeyboardEvent) {
    if (!recordingShortcut) return
    event.preventDefault()
    if (event.key === 'Escape') {
      cancelRecordingShortcut()
      return
    }
    if (event.key === 'Control' || event.key === 'Alt' || event.key === 'Shift' || event.key === 'Meta') return
    const token = tokenForCode(event.code)
    if (!token) return
    const modifiers: string[] = []
    if (event.ctrlKey) modifiers.push('Ctrl')
    if (event.altKey) modifiers.push('Alt')
    if (event.shiftKey) modifiers.push('Shift')
    if (modifiers.length === 0) return
    recordingShortcut = false
    onUpdateQuickAccessShortcut([...modifiers, token].join('+'))
  }

  function formatBytes(bytes: number) {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${Math.max(0.1, bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  $: websiteIconCacheLabel = websiteIconCacheEntryCount === 0
    ? 'The cache is empty.'
    : `${websiteIconCacheIconCount} ${websiteIconCacheIconCount === 1 ? 'icon' : 'icons'} cached (${formatBytes(websiteIconCacheSizeBytes)}).`
</script>

<svelte:window on:keydown={handleShortcutKeydown} />

<div class="settings-groups">
  <section class="settings-group" aria-labelledby="settings-group-general-appearance">
    <h3 id="settings-group-general-appearance">Appearance</h3>
    <div class="settings-list">
      <article>
        <div class="setting-copy"><strong>Theme</strong><p>Match your system, or force light or dark.</p></div>
        <div class="theme-toggle" role="group" aria-label="Theme" use:slidingSelection><button type="button" class:active={theme === 'light'} aria-pressed={theme === 'light'} aria-label="Light" title="Light" on:click={() => onSetTheme('light')}><Icon name="sun" size={15} /></button><button type="button" class:active={theme === 'auto'} aria-pressed={theme === 'auto'} aria-label="System" title="System" on:click={() => onSetTheme('auto')}><Icon name="monitor" size={15} /></button><button type="button" class:active={theme === 'dark'} aria-pressed={theme === 'dark'} aria-label="Dark" title="Dark" on:click={() => onSetTheme('dark')}><Icon name="moon" size={15} /></button></div>
      </article>
      <article>
        <div class="setting-copy"><strong>Website icons</strong><p>Download icons only as they come into view, then reuse Sesame's local copy for up to 30 days. The first request still reveals the saved domain to that site. Sesame accepts only ICO and PNG icons, and it decodes each one itself before showing it. {websiteIconCacheLabel}</p></div>
        <div class="website-icon-actions"><button type="button" class="text-button" disabled={websiteIconCacheWorking || websiteIconCacheEntryCount === 0} on:click={onClearWebsiteIconCache}>Clear cache</button><button type="button" class="switch" class:active={siteIconsEnabled} role="switch" aria-checked={siteIconsEnabled} aria-label="Website icons" disabled={siteIconsWorking} on:click={() => onSetSiteIconsEnabled(!siteIconsEnabled)}><span></span></button></div>
      </article>
    </div>
  </section>
  <section class="settings-group" aria-labelledby="settings-group-general-app">
    <h3 id="settings-group-general-app">This app</h3>
    <div class="settings-list">
      <article>
        <div class="setting-copy"><strong>Keep Sesame in the tray</strong><p>Closing the window keeps it running. Turn off to quit on close.</p></div>
        <button type="button" class="switch" class:active={keepInTray} role="switch" aria-checked={keepInTray} aria-label="Keep Sesame in the tray" disabled={trayWorking} on:click={onToggleTray}><span></span></button>
      </article>
      <article>
        <div class="setting-copy"><strong>Start at sign-in</strong><p>Opens in the tray when you sign in. The vault stays locked until you unlock it.</p></div>
        <button type="button" class="switch" class:active={autostartEnabled} role="switch" aria-checked={autostartEnabled} aria-label="Start at sign-in" disabled={autostartWorking} on:click={onToggleAutostart}><span></span></button>
      </article>
      <article>
        {#if $platformCapabilities.desktopUpdates}
          <div class="setting-copy"><strong>Desktop updates</strong><p>{updateWorking && updateProgress ? `Downloading verified update${updateProgress.totalBytes ? `, ${Math.min(100, Math.round(updateProgress.downloadedBytes / updateProgress.totalBytes * 100))}% complete.` : '…'}` : desktopUpdate.available ? `Version ${desktopUpdate.version} is ready to install.${desktopUpdate.body ? ` ${desktopUpdate.body}` : ''}` : `Check the configured signed release feed. No Sesame account is required.${freshnessNote ? ` ${freshnessNote}` : ''}`}</p></div>
          {#if desktopUpdate.available}<button type="button" class="text-button" disabled={updateWorking} on:click={onInstallUpdate}>{updateWorking ? 'Installing…' : 'Install update'}</button>{:else}<button type="button" class="text-button" disabled={updateWorking} on:click={onCheckForUpdate}>{updateWorking ? 'Checking…' : 'Check now'}</button>{/if}
        {:else}
          <div class="setting-copy"><strong>Desktop updates</strong><p>Sesame does not update itself on this system. You are running {$appVersion ? `version ${$appVersion}` : 'this build'}. Update it the way you installed it to get security fixes.</p></div>
        {/if}
      </article>
    </div>
  </section>
  <section class="settings-group" aria-labelledby="settings-group-general-shortcuts">
    <h3 id="settings-group-general-shortcuts">Shortcuts</h3>
    <div class="settings-list">
      {#if $platformCapabilities.quickAccessShortcut}
      <article>
        <div class="setting-copy"><strong>Quick access shortcut</strong><p>Opens the quick access popup from anywhere, even while Sesame is in the tray.</p></div>
        <button type="button" class="text-button" disabled={quickAccessShortcutWorking} on:click={recordingShortcut ? cancelRecordingShortcut : startRecordingShortcut}>
          {recordingShortcut ? 'Press keys (Esc cancels)' : formatAccelerator(quickAccessShortcut)}
        </button>
      </article>
      {/if}
      <article>
        <div class="setting-copy">
          <strong>Keyboard shortcuts</strong>
          <dl class="shortcut-list">
            {#each SHORTCUTS as shortcut (shortcut.keys)}
              <div><dt>{shortcut.label}</dt><dd>{#each shortcut.keys.split(' ') as key (key)}<kbd>{key}</kbd>{/each}</dd></div>
            {/each}
            <div><dt>Search the list</dt><dd><kbd>/</kbd></dd></div>
          </dl>
        </div>
      </article>
    </div>
  </section>
</div>

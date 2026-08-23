<script lang="ts">
  import { tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import SyncPreviewHost from './SyncPreviewHost.svelte'
  import SyncVaultStorageRow from './SyncVaultStorageRow.svelte'
  import { SYNC_PREVIEW_AVAILABLE, SYNC_STATUS_URL } from '../app-meta'
  import { SHORTCUTS } from '../shortcuts'
  import { platformCapabilities } from '../platform'
  import type { BrowserIntegrationStatus, DesktopUpdateProgress, DesktopUpdateStatus, DiagnosticStatus, ServiceConnectionStatus, Theme } from '../types'
  import AccountConnectionSetting from './AccountConnectionSetting.svelte'
  import BrowserIntegrationSetting from './BrowserIntegrationSetting.svelte'

  export let theme: Theme = 'auto'
  export let siteIconsEnabled = false
  export let autoLockMinutes = 5
  export let autoLockOptions: number[] = []
  export let clipboardClearSeconds = 30
  export let clipboardClearOptions: number[] = []
  export let onSetClipboardClearSeconds: (seconds: number) => void
  export let pinUnlockAvailable = false
  export let pinWorking = false
  export let onTogglePin: () => void
  export let helloUnlockAvailable = false
  export let helloWorking = false
  export let onToggleHello: () => void
  export let onChangeMasterPassword: () => void
  export let keepInTray = true
  export let trayWorking = false
  export let onToggleTray: () => void
  export let autostartEnabled = false
  export let autostartWorking = false
  export let onToggleAutostart: () => void
  export let quickAccessShortcut = 'Ctrl+Alt+S'
  export let quickAccessShortcutWorking = false
  export let onUpdateQuickAccessShortcut: (accelerator: string) => void
  export let onSetTheme: (value: Theme) => void
  export let onSetSiteIconsEnabled: (enabled: boolean) => void
  export let websiteIconCacheWorking = false
  export let websiteIconCacheEntryCount = 0
  export let websiteIconCacheIconCount = 0
  export let websiteIconCacheSizeBytes = 0
  export let onClearWebsiteIconCache: () => void
  export let onSetAutoLockMinutes: (minutes: number) => void
  export let onManageData: () => void
  export let diagnosticEventCount = 0
  export let diagnosticErrorCount = 0
  export let diagnosticWorking = false
  export let diagnosticStatus: DiagnosticStatus = { exists: false, eventCount: 0, errorCount: 0, sizeBytes: 0, localOnly: true, byOperation: [], byCode: [], recent: [] }
  export let onExportDiagnostics: () => void
  export let onClearDiagnostics: () => void
  export let serviceConnection: ServiceConnectionStatus = { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }
  export let serviceWorking = false
  export let onLinkService: (code: string) => void
  export let onDisconnectService: () => void
  export let onRefreshService: () => void
  export let serviceConnectionAvailable = true
  export let desktopUpdate: DesktopUpdateStatus = { available: false }
  export let updateWorking = false
  export let updateProgress: DesktopUpdateProgress | null = null
  export let onCheckForUpdate: () => void
  export let onInstallUpdate: () => void
  export let browserIntegration: BrowserIntegrationStatus | null = null
  export let browserIntegrationWorking = false
  export let onRefreshBrowserIntegration: () => void
  export let onRepairBrowserIntegration: () => void
  export let onOpenWebsite: (url: string) => void

  const syncStatusUrl = SYNC_STATUS_URL

  type TabId = 'general' | 'security' | 'connections' | 'data'
  const tabs: { id: TabId; label: string; icon: string }[] = [
    { id: 'general', label: 'General', icon: 'monitor' },
    { id: 'security', label: 'Security', icon: 'lock' },
    { id: 'connections', label: 'Connections', icon: 'globe' },
    { id: 'data', label: 'Data', icon: 'shield' },
  ]
  let tab: TabId = 'general'
  const tabButtons: HTMLButtonElement[] = []
  let recordingShortcut = false

  function formatAccelerator(value: string): string {
    return value.split('+').join(' + ')
  }

  function diagnosticTime(timestamp: number): string {
    return new Date(timestamp * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
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

  async function handleTabKeydown(event: KeyboardEvent, index: number) {
    let nextIndex: number | null = null
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % tabs.length
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + tabs.length) % tabs.length
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = tabs.length - 1
    if (nextIndex === null) return

    event.preventDefault()
    tab = tabs[nextIndex].id
    await tick()
    tabButtons[nextIndex]?.focus()
  }


  function slidingSelection(node: HTMLElement) {
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
</script>

<svelte:window on:keydown={handleShortcutKeydown} />

<section class="settings-view">
  <div class="settings-tabs" role="tablist" aria-label="Settings sections">
    {#each tabs as item, index (item.id)}
      <button
        bind:this={tabButtons[index]}
        id={`settings-tab-${item.id}`}
        role="tab"
        type="button"
        class:active={tab === item.id}
        aria-selected={tab === item.id}
        aria-controls={`settings-panel-${item.id}`}
        tabindex={tab === item.id ? 0 : -1}
        on:click={() => (tab = item.id)}
        on:keydown={(event) => handleTabKeydown(event, index)}
      >
        <Icon name={item.icon} size={15} strokeWidth={1.9} />{item.label}
      </button>
    {/each}
  </div>

  <div id={`settings-panel-${tab}`} class="settings-panel" role="tabpanel" aria-labelledby={`settings-tab-${tab}`}>
    {#key tab}
    {#if tab === 'general'}
      <div class="settings-groups">
        <section class="settings-group" aria-labelledby="settings-group-general-appearance">
          <h3 id="settings-group-general-appearance">Appearance</h3>
          <div class="settings-list">
            <article>
              <span class="settings-icon"><Icon name="monitor" size={17} /></span>
              <div class="setting-copy"><strong>Theme</strong><p>Match your system, or force light or dark.</p></div>
              <div class="theme-toggle" role="group" aria-label="Theme" use:slidingSelection><button type="button" class:active={theme === 'light'} aria-pressed={theme === 'light'} aria-label="Light" on:click={() => onSetTheme('light')}><Icon name="sun" size={15} /></button><button type="button" class:active={theme === 'auto'} aria-pressed={theme === 'auto'} aria-label="System" on:click={() => onSetTheme('auto')}><Icon name="monitor" size={15} /></button><button type="button" class:active={theme === 'dark'} aria-pressed={theme === 'dark'} aria-label="Dark" on:click={() => onSetTheme('dark')}><Icon name="moon" size={15} /></button></div>
            </article>
            <article>
              <span class="settings-icon"><Icon name="globe" size={17} /></span>
              <div class="setting-copy"><strong>Website icons</strong><p>Download icons only as they come into view, then reuse Sesame's local copy for up to 30 days. The first request still reveals the saved domain to that site. {websiteIconCacheLabel}</p></div>
              <div class="website-icon-actions"><button type="button" class="text-button" disabled={websiteIconCacheWorking || websiteIconCacheEntryCount === 0} on:click={onClearWebsiteIconCache}>Clear cache</button><button type="button" class="switch" class:active={siteIconsEnabled} role="switch" aria-checked={siteIconsEnabled} aria-label="Website icons" on:click={() => onSetSiteIconsEnabled(!siteIconsEnabled)}><span></span></button></div>
            </article>
          </div>
        </section>
        <section class="settings-group" aria-labelledby="settings-group-general-app">
          <h3 id="settings-group-general-app">This app</h3>
          <div class="settings-list">
            <article>
              <span class="settings-icon"><Icon name="monitor" size={16} /></span>
              <div class="setting-copy"><strong>Keep Sesame in the tray</strong><p>Closing the window keeps it running. Turn off to quit on close.</p></div>
              <button type="button" class="switch" class:active={keepInTray} role="switch" aria-checked={keepInTray} aria-label="Keep Sesame in the tray" disabled={trayWorking} on:click={onToggleTray}><span></span></button>
            </article>
            <article>
              <span class="settings-icon"><Icon name="monitor" size={16} /></span>
              <div class="setting-copy"><strong>Start at sign-in</strong><p>Opens in the tray when you sign in. The vault stays locked until you unlock it.</p></div>
              <button type="button" class="switch" class:active={autostartEnabled} role="switch" aria-checked={autostartEnabled} aria-label="Start at sign-in" disabled={autostartWorking} on:click={onToggleAutostart}><span></span></button>
            </article>
            <article>
              <span class="settings-icon"><Icon name="key" size={16} /></span>
              <div class="setting-copy"><strong>Quick access shortcut</strong><p>Opens the quick access popup from anywhere, even while Sesame is in the tray.</p></div>
              <button type="button" class="text-button" disabled={quickAccessShortcutWorking} on:click={recordingShortcut ? cancelRecordingShortcut : startRecordingShortcut}>
                {recordingShortcut ? 'Press keys (Esc cancels)' : formatAccelerator(quickAccessShortcut)}
              </button>
            </article>
            <article>
              <span class="settings-icon"><Icon name="archive" size={16} /></span>
              <div class="setting-copy"><strong>Desktop updates</strong><p>{updateWorking && updateProgress ? `Downloading verified update${updateProgress.totalBytes ? `, ${Math.min(100, Math.round(updateProgress.downloadedBytes / updateProgress.totalBytes * 100))}% complete.` : '...'}` : desktopUpdate.available ? `Version ${desktopUpdate.version} is ready to install.${desktopUpdate.body ? ` ${desktopUpdate.body}` : ''}` : 'Check the configured signed release feed. No Sesame account is required.'}</p></div>
              {#if desktopUpdate.available}<button type="button" class="text-button" disabled={updateWorking} on:click={onInstallUpdate}>{updateWorking ? 'Installing...' : 'Install update'}</button>{:else}<button type="button" class="text-button" disabled={updateWorking} on:click={onCheckForUpdate}>{updateWorking ? 'Checking...' : 'Check now'}</button>{/if}
            </article>
            <article>
              <span class="settings-icon"><Icon name="key" size={16} /></span>
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
    {:else if tab === 'security'}
      <div class="settings-groups">
        <section class="settings-group" aria-labelledby="settings-group-security-device">
          <h3 id="settings-group-security-device">This device</h3>
          <div class="settings-list">
            {#if $platformCapabilities.sessionAutoLock}
            <article>
              <span class="settings-icon"><Icon name="lock" size={16} /></span>
              <div class="setting-copy"><strong>Automatic lock</strong><p>Lock the vault after a period without keyboard or pointer activity.</p></div>
              <div class="auto-lock-options" role="group" aria-label="Automatic lock delay" use:slidingSelection>{#each autoLockOptions as minutes (minutes)}<button type="button" class:active={autoLockMinutes === minutes} aria-pressed={autoLockMinutes === minutes} aria-label={`${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`} on:click={() => onSetAutoLockMinutes(minutes)}>{minutes}m</button>{/each}</div>
            </article>
            {/if}
            {#if $platformCapabilities.pinUnlock}
            <article>
              <span class="settings-icon"><Icon name="key" size={16} /></span>
              <div class="setting-copy"><strong>Unlock with PIN</strong><p>Use a six-digit PIN on this device. Your master password or recovery kit remains available.</p></div>
              <button type="button" class="switch" class:active={pinUnlockAvailable} role="switch" aria-checked={pinUnlockAvailable} aria-label="Unlock with PIN" disabled={pinWorking} on:click={onTogglePin}><span></span></button>
            </article>
            {/if}
            {#if $platformCapabilities.biometricUnlock}
            <article>
              <span class="settings-icon"><Icon name="key" size={16} /></span>
              <div class="setting-copy"><strong>Unlock with Windows Hello</strong><p>Use this device's Windows Hello gesture. Your master password or recovery kit remains available, and Sesame never receives your biometric data.</p></div>
              <button type="button" class="switch" class:active={helloUnlockAvailable} role="switch" aria-checked={helloUnlockAvailable} aria-label="Unlock with Windows Hello" disabled={helloWorking} on:click={onToggleHello}><span></span></button>
            </article>
            {/if}
            <article>
              <span class="settings-icon"><Icon name="copy" size={16} /></span>
              <div class="setting-copy"><strong>Clipboard timeout</strong><p>How long a copied password or code stays on the clipboard before Sesame clears it.</p></div>
              <div class="clipboard-clear-options" role="group" aria-label="Clipboard clear delay" use:slidingSelection>{#each clipboardClearOptions as seconds (seconds)}<button type="button" class:active={clipboardClearSeconds === seconds} aria-pressed={clipboardClearSeconds === seconds} aria-label={`${seconds} seconds`} on:click={() => onSetClipboardClearSeconds(seconds)}>{seconds}s</button>{/each}</div>
            </article>
          </div>
        </section>
        <section class="settings-group" aria-labelledby="settings-group-security-key">
          <h3 id="settings-group-security-key">Your vault key</h3>
          <div class="settings-list">
            <article>
              <span class="settings-icon"><Icon name="key" size={16} /></span>
              <div class="setting-copy"><strong>Master password</strong><p>Replace your master password and get a fresh recovery kit.</p></div>
              <button type="button" class="secondary-button settings-manage" on:click={onChangeMasterPassword}>Change</button>
            </article>
          </div>
        </section>
      </div>
    {:else if tab === 'connections'}
      <div class="settings-groups">
        {#if !browserIntegration?.ready}
          <section class="settings-group" aria-labelledby="settings-group-connections-browser">
            <h3 id="settings-group-connections-browser">Browser</h3>
            <div class="settings-list">
              <BrowserIntegrationSetting
                desktopAvailable={serviceConnectionAvailable}
                status={browserIntegration}
                working={browserIntegrationWorking}
                onRefresh={onRefreshBrowserIntegration}
                onRepair={onRepairBrowserIntegration}
              />
            </div>
          </section>
        {/if}
        <section class="settings-group" aria-labelledby="settings-group-connections-account">
          <h3 id="settings-group-connections-account">Sesame account</h3>
          <div class="settings-list">
            <AccountConnectionSetting connection={serviceConnection} working={serviceWorking} available={serviceConnectionAvailable} onConnect={onLinkService} onDisconnect={onDisconnectService} onRefresh={onRefreshService} />
            {#if SYNC_PREVIEW_AVAILABLE}<SyncPreviewHost />{/if}
            <!-- Renders no Sync control and imports nothing from the Sync client. -->
            {#if !SYNC_PREVIEW_AVAILABLE}
              <article>
                <span class="settings-icon"><Icon name="refresh" size={16} /></span>
                <div class="setting-copy">
                  <strong>Sesame Sync</strong>
                  {#if serviceConnection.syncAvailable}
                    <p>Your account can use Sesame Sync. This version of Sesame cannot, so install a newer one before turning it on.</p>
                  {:else}
                    <p>An encrypted copy of your vault that your other devices can read and Sesame cannot. It is not open yet: the protocol needs an independent review first.</p>
                  {/if}
                </div>
                <div class="diagnostic-actions">
                  {#if syncStatusUrl}
                    <button type="button" class="text-button" on:click={() => onOpenWebsite(syncStatusUrl)}>Check status</button>
                  {/if}
                  <span class="status-pill">{serviceConnection.syncAvailable ? 'Update needed' : 'Not available'}</span>
                </div>
              </article>
            {/if}
          </div>
        </section>
      </div>
    {:else}
      <div class="settings-groups">
        <section class="settings-group" aria-labelledby="settings-group-data-vault">
          <h3 id="settings-group-data-vault">Your vault</h3>
          <div class="settings-list">
            {#if SYNC_PREVIEW_AVAILABLE}
              <SyncVaultStorageRow />
            {:else}
              <article>
                <span class="settings-icon"><Icon name="shield" size={17} /></span>
                <div class="setting-copy"><strong>Local-only vault</strong><p>Your vault is stored on this device. Sesame has no cloud copy.</p></div>
                <span class="status-pill">Active</span>
              </article>
            {/if}
            <article>
              <span class="settings-icon"><Icon name="archive" size={16} /></span>
              <div class="setting-copy"><strong>Export and deletion</strong><p>Export a readable copy or remove Sesame data from this device.</p></div>
              <button type="button" class="secondary-button settings-manage" on:click={onManageData}>Manage</button>
            </article>
          </div>
        </section>
        <section class="settings-group" aria-labelledby="settings-group-data-diagnostics">
          <h3 id="settings-group-data-diagnostics">Diagnostics</h3>
          <div class="settings-list">
            <article class="settings-row-expandable">
              <span class="settings-icon"><Icon name="file-key" size={16} /></span>
              <div class="setting-copy"><strong>Local diagnostics</strong><p>{diagnosticEventCount} {diagnosticEventCount === 1 ? 'event' : 'events'} stored, {diagnosticErrorCount} flagged. Routine events clear after a day; flagged ones are kept for support. Events record categories and timing only, never vault contents or raw errors.</p></div>
              <div class="diagnostic-actions"><button type="button" class="secondary-button settings-manage" on:click={onExportDiagnostics} disabled={diagnosticWorking || diagnosticEventCount === 0}>Export</button><button type="button" class="text-button" on:click={onClearDiagnostics} disabled={diagnosticWorking || diagnosticEventCount === 0}>Clear</button></div>
              {#if diagnosticStatus.recent.length > 0}
                <details class="diagnostics-detail">
                  <summary><Icon name="chevron-right" size={14} />Recent activity</summary>
                  {#if diagnosticStatus.byOperation.length > 0}
                    <div class="diagnostics-breakdown">
                      <strong>By area</strong>
                      <ul>
                        {#each diagnosticStatus.byOperation as entry, i (i)}
                          <li><span>{entry.operation}</span><small>{entry.count} event{entry.count === 1 ? '' : 's'}{entry.errorCount > 0 ? ` · ${entry.errorCount} flagged` : ''}</small></li>
                        {/each}
                      </ul>
                    </div>
                  {/if}
                  {#if diagnosticStatus.byCode.length > 0}
                    <div class="diagnostics-breakdown">
                      <strong>Codes</strong>
                      <ul>
                        {#each diagnosticStatus.byCode as entry, i (i)}
                          <li><span class="diagnostic-code" class:error={entry.level === 'error'} class:warn={entry.level === 'warn'}>{entry.code}</span><small>{entry.count} {entry.count === 1 ? 'time' : 'times'}</small></li>
                        {/each}
                      </ul>
                    </div>
                  {/if}
                  <div class="diagnostics-breakdown">
                    <strong>Recent events</strong>
                    <ul>
                      {#each diagnosticStatus.recent as event, i (i)}
                        <li><span class="diagnostic-code" class:error={event.level === 'error'} class:warn={event.level === 'warn'}>{event.code}</span><small>{event.operation} · {diagnosticTime(event.timestamp)}</small></li>
                      {/each}
                    </ul>
                  </div>
                  <p class="tiny-note">Each launch gets one random session id, which groups these events in the exported file. Codes and categories only, never vault contents.</p>
                </details>
              {/if}
            </article>
          </div>
        </section>
      </div>
    {/if}
    {/key}
  </div>
</section>

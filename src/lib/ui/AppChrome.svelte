<script lang="ts">
  import { platformCapabilities } from '../platform'
  import { controlWindow } from '../vault'

  export let keepInTray = true
  export let idleWarningSeconds: number | null = null
  export let onStayUnlocked: () => void = () => {}
  export let preview = false
  /// Sync status text; undefined in every build where Sync is disabled.
  export let syncStatusLabel: string | undefined = undefined

  $: contextLabel = syncStatusLabel ?? (preview ? 'Preview mode' : 'Local vault')
</script>

<header class="app-chrome">
  <div class="chrome-brand" data-tauri-drag-region>
    <img class="chrome-mark" src="/favicon.svg" alt="" />
    <span>Sesame</span>
    <span class="chrome-separator">/</span>
    <span class="chrome-context">{contextLabel}</span>
  </div>
  <div class="chrome-drag-space" data-tauri-drag-region></div>
  <!-- Only real input dismisses: the button defers the lock, no command behind it. See src-tauri/src/session_guard.rs. -->
  {#if idleWarningSeconds !== null}
    <div class="idle-warning" role="alert">
      <span>Locking in {idleWarningSeconds}s</span>
      <button type="button" on:click={onStayUnlocked}>Stay unlocked</button>
    </div>
    <div class="chrome-drag-space" data-tauri-drag-region></div>
  {/if}
  <div class="window-controls" role="group" aria-label="Window controls">
    {#if $platformCapabilities.windowControls}
      <button type="button" class="window-control" aria-label="Minimize" on:click={() => controlWindow('minimize')}><svg viewBox="0 0 10 10" aria-hidden="true" focusable="false"><path d="M2 5h6" /></svg></button>
      <button type="button" class="window-control" aria-label="Maximize or restore" on:click={() => controlWindow('toggle-maximize')}><svg viewBox="0 0 10 10" aria-hidden="true" focusable="false"><rect x="2.2" y="2.2" width="5.6" height="5.6" rx=".4" /></svg></button>
    {/if}
    <button type="button" class="window-control close" aria-label={keepInTray ? 'Hide Sesame to tray' : 'Close Sesame'} title={keepInTray ? 'Hide Sesame to tray' : 'Close Sesame'} on:click={() => controlWindow('close')}><svg viewBox="0 0 10 10" aria-hidden="true" focusable="false"><path d="M2.2 2.2 7.8 7.8M7.8 2.2 2.2 7.8" /></svg></button>
  </div>
</header>

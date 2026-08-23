<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { BrowserIntegrationStatus } from '../types'

  export let desktopAvailable = true
  export let status: BrowserIntegrationStatus | null = null
  export let working = false
  export let onRefresh: () => void
  export let onRepair: () => void

  $: ready = desktopAvailable && status?.ready === true
  $: canRepair = desktopAvailable && (status?.code === 'manifestMissing' || status?.code === 'registrationMissing')
  $: statusLabel = !desktopAvailable
    ? 'Desktop only'
    : status?.code === 'unsupported'
      ? 'Not on this system'
      : status?.code === 'hostMissing'
        ? 'Installation incomplete'
        : working && !status
          ? 'Checking…'
          : ready
            ? 'No repair needed'
            : status
              ? 'Needs repair'
              : 'Not checked'

  function description() {
    if (!desktopAvailable) return 'Browser connection is available from the installed desktop app.'
    if (status?.code === 'unsupported') return 'Browser connection is not available on this operating system yet. Copy and paste still works.'
    if (!status) return 'Checking the local browser connection.'
    if (status.ready) return 'The native connection is registered for Chrome and Edge. This does not confirm that the browser extension is installed.'
    if (status.code === 'hostMissing') return 'This Sesame installation is missing its browser connection component. Reinstall or repair the desktop app.'
    if (status.code === 'manifestMissing') return 'Could not prepare the local browser connection files.'
    return 'Chrome or Edge registration is incomplete. Can be repaired without an administrator account.'
  }
</script>

<article class="settings-browser-row">
  <span class="settings-icon"><Icon name="browser" size={17} /></span>
  <div class="setting-copy browser-setting-copy">
    <strong>Browser autofill setup</strong>
    <p>{description()}</p>

    {#if desktopAvailable && status && !status.ready && status.code !== 'hostMissing' && status.code !== 'unsupported'}
      <ul class="browser-checks" aria-label="Browser connection checks">
        <li class:ok={status.hostAvailable}><Icon name={status.hostAvailable ? 'check' : 'alert'} size={13} /> Desktop helper</li>
        <li class:ok={status.manifestReady}><Icon name={status.manifestReady ? 'check' : 'alert'} size={13} /> Connection files</li>
        <li class:ok={status.chromeRegistered}><Icon name={status.chromeRegistered ? 'check' : 'alert'} size={13} /> Chrome registration</li>
        <li class:ok={status.edgeRegistered}><Icon name={status.edgeRegistered ? 'check' : 'alert'} size={13} /> Edge registration</li>
        <li class:ok={status.firefoxRegistered}><Icon name={status.firefoxRegistered ? 'check' : 'alert'} size={13} /> Firefox registration</li>
      </ul>
    {/if}
  </div>
  <div class="browser-setting-actions">
    <span class:warning={!ready && status?.supported} class:neutral={!ready && !status?.supported} class="status-pill">{statusLabel}</span>
    {#if canRepair}
      <button type="button" class="secondary-button settings-manage" disabled={working} on:click={onRepair}>
        {working ? 'Repairing…' : 'Repair connection'}
      </button>
    {:else if desktopAvailable}
      <button type="button" class="text-button" disabled={working} on:click={onRefresh}>
        {working ? 'Checking…' : 'Recheck desktop setup'}
      </button>
    {/if}
  </div>
</article>

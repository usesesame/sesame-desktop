<script lang="ts">
  import Icon from '../Icon.svelte'
  import { platformCapabilities } from '../platform'
  import type { ServiceConnectionStatus } from '../types'

  export let connection: ServiceConnectionStatus
  export let working = false
  export let available = true
  export let onConnect: (code: string) => void
  export let onDisconnect: () => void
  export let onRefresh: () => void

  let desktopCode = ''

  function connect() {
    const code = desktopCode.trim()
    if (!code || working) return
    onConnect(code)
  }

  $: description = connection.state === 'connected'
    ? `Connected as ${connection.deviceName || 'this desktop'}.`
    : connection.state === 'suspended'
      ? 'This account is suspended. The local vault still works, and the link will resume when access is restored.'
      : connection.state === 'revoked'
        ? 'This desktop link was revoked. Use a new one-time code to reconnect.'
        : connection.state === 'rateLimited'
          ? 'Status checks are temporarily limited. Wait a moment, then try again.'
          : connection.state === 'serviceUnavailable'
            ? 'The account service is temporarily unavailable. Your local vault is unaffected.'
            : connection.state === 'needsAttention'
              ? 'The account service rejected this connection. Retry, then reconnect if it continues.'
              : connection.state === 'offline'
                ? 'Sesame could not reach the account service. Check your connection and retry.'
                : 'Link this desktop with a one-time code from usesesame.app/account. This does not upload your vault.'
  $: statusLabel = connection.state === 'connected' ? 'Connected'
    : connection.state === 'suspended' ? 'Suspended'
      : connection.state === 'rateLimited' ? 'Try later'
        : connection.state === 'serviceUnavailable' ? 'Unavailable'
          : connection.state === 'needsAttention' ? 'Check link'
            : connection.state === 'offline' ? 'Offline' : 'Reconnect'
</script>

<article class="settings-service-row">
  <span class="settings-icon"><Icon name="user" size={17} /></span>
  <div class="setting-copy">
    <strong>Sesame account</strong>
    <p>
      {#if !available}
        Account linking is available in the installed desktop app.
      {:else if !$platformCapabilities.accountLinking}
        Account linking is not available on this operating system yet. Your local vault is unaffected.
      {:else}
        {description}
      {/if}
    </p>
  </div>

  {#if !available}
    <span class="status-pill neutral">Desktop only</span>
  {:else if !$platformCapabilities.accountLinking}
    <span class="status-pill neutral">Not on this system</span>
  {:else if connection.connected}
    <div class="settings-service-actions">
      <span class:offline={connection.state === 'offline' || connection.state === 'serviceUnavailable' || connection.state === 'rateLimited'} class:warning={connection.state === 'suspended' || connection.state === 'needsAttention'} class="status-pill">{statusLabel}</span>
      {#if connection.state !== 'connected'}
        <button type="button" class="secondary-button settings-manage" on:click={onRefresh} disabled={working} aria-busy={working}>{#if working}<span class="refresh-spinner" aria-hidden="true"></span>{:else}<Icon name="refresh" size={14} />{/if} Retry</button>
      {/if}
      <button type="button" class="text-button" on:click={onDisconnect} disabled={working}>{connection.state === 'connected' ? 'Disconnect' : 'Remove link'}</button>
    </div>
  {:else}
    <form class="settings-service-connect" on:submit|preventDefault={connect}>
      <input
        name="desktop-code"
        aria-label="One-time desktop code"
        bind:value={desktopCode}
        placeholder="One-time code"
        autocomplete="off"
        spellcheck="false"
        disabled={working}
      />
      <button type="submit" class="secondary-button settings-manage" disabled={working || !desktopCode.trim()}>
        {working ? 'Connecting…' : connection.state === 'revoked' ? 'Reconnect' : 'Connect'}
      </button>
    </form>
  {/if}
</article>

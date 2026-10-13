<script lang="ts">
  import { groupedFingerprint, pairingInputHasCode } from '../server-pairing'
  import type { ServerInspection, ServiceConnectionStatus } from '../types'

  export let connection: ServiceConnectionStatus
  export let working = false
  export let available = true
  export let onInspect: (input: string) => Promise<ServerInspection | null>
  export let onConnect: (input: string, code: string, fingerprint: string) => Promise<boolean>
  export let onDisconnect: () => void
  export let onRefresh: () => void

  let input = ''
  let code = ''
  let inspection: ServerInspection | null = null

  $: custom = Boolean(connection.serverAddress)
  $: accountLinked = connection.connected && !custom
  $: needsCode = !pairingInputHasCode(input)
  $: if (!needsCode && code) code = ''
  $: canCheck = input.trim().length > 0 && (!needsCode || code.trim().length > 0) && !working

  $: problem = connection.state === 'serverKeyChanged'
    ? 'This server now uses a different key than the one this desktop pinned. Nothing was sent to it. Disconnect, then pair again only if you expect the change.'
    : connection.state === 'serverClockDiffers'
      ? "This computer's clock and the server's clock differ. Check the date and time on both, then retry."
      : connection.state === 'serverIncompatible'
      ? 'This server and this version of Sesame cannot work together. Update whichever one is older.'
      : connection.state === 'offline'
        ? 'Sesame could not reach the server.'
        : connection.state === 'needsAttention'
          ? 'The server did not answer as expected. Retry, or disconnect and pair again.'
          : ''

  $: endedNote = connection.state === 'expired'
    ? 'The link between this desktop and the server expired. Pair again with a new code.'
    : connection.state === 'revoked'
      ? 'This desktop was removed on the server. Pair again with a new code.'
      : ''

  async function check() {
    if (!canCheck) return
    inspection = await onInspect(input.trim())
  }

  async function pair() {
    if (!inspection || working) return
    const paired = await onConnect(input.trim(), needsCode ? code.trim() : '', inspection.fingerprint)
    if (paired) reset()
  }

  function reset() {
    inspection = null
    input = ''
    code = ''
  }
</script>

<article class="settings-server-row">
  {#if !available}
    <div class="setting-copy">
      <strong>Your own server</strong>
      <p>Pairing with your own server is available in the installed desktop app.</p>
    </div>
  {:else if custom}
    <div class="setting-copy">
      <strong>{connection.serverName || 'Your own server'}</strong>
      <p>Connected to <span class="server-address">{connection.serverAddress}</span> as {connection.deviceName || 'this desktop'}.</p>
      {#if problem}<p class="server-problem">{problem}</p>{/if}
      {#if connection.serverFingerprint}
        <dl class="server-facts">
          <dt>Fingerprint you confirmed</dt>
          <dd class="server-fingerprint">{groupedFingerprint(connection.serverFingerprint)}</dd>
        </dl>
      {/if}
    </div>
    <div class="settings-service-actions">
      {#if connection.state !== 'connected'}
        <button type="button" class="secondary-button settings-manage" on:click={onRefresh} disabled={working}>Retry</button>
      {/if}
      <button type="button" class="text-button" on:click={onDisconnect} disabled={working}>{connection.state === 'connected' ? 'Disconnect' : 'Remove link'}</button>
    </div>
  {:else if accountLinked}
    <div class="setting-copy">
      <strong>Your own server</strong>
      <p>This desktop is linked to a Sesame account. Disconnect it before pairing with a server you run.</p>
    </div>
  {:else if inspection}
    <div class="setting-copy server-confirm">
      <strong>Check this server before you pair</strong>
      <dl class="server-facts">
        <dt>Address</dt>
        <dd class="server-address">{inspection.address}</dd>
        {#if inspection.name}
          <dt>Name</dt>
          <dd>{inspection.name}</dd>
        {/if}
        <dt>Fingerprint</dt>
        <dd class="server-fingerprint">{groupedFingerprint(inspection.fingerprint)}</dd>
      </dl>
      {#if inspection.fingerprintInLink}
        <p>The fingerprint matches the one in your pairing link.</p>
      {:else}
        <p class="server-problem">Your link did not include a fingerprint. Compare this one with the fingerprint your server shows before you continue.</p>
      {/if}
      {#if inspection.plainHttp}
        <p>This address uses plain http and is on this computer.</p>
      {/if}
      <p>Sesame sends the one-time code and this device's name to this address. Your vault is not uploaded. Pair only if you run this server or trust the person who does.</p>
      <div class="settings-service-actions">
        <button type="button" class="primary-button settings-manage" on:click={pair} disabled={working}>{working ? 'Pairing…' : 'Pair with this server'}</button>
        <button type="button" class="text-button" on:click={reset} disabled={working}>Cancel</button>
      </div>
    </div>
  {:else}
    <form class="setting-copy server-form" on:submit|preventDefault={check}>
      <strong>Your own server</strong>
      <p>Paste the pairing link from your server's console, or enter its address and a one-time code. Sesame shows you the server before it sends anything but a read of its public settings.</p>
      {#if endedNote}<p class="server-problem">{endedNote}</p>{/if}
      <label for="own-server-input">Pairing link or server address</label>
      <input
        id="own-server-input"
        name="own-server-input"
        bind:value={input}
        placeholder="https://sesame.example.com"
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
        disabled={working}
      />
      {#if input.trim() && needsCode}
        <label for="own-server-code">One-time pairing code</label>
        <input
          id="own-server-code"
          name="own-server-code"
          bind:value={code}
          autocomplete="off"
          spellcheck="false"
          disabled={working}
        />
      {/if}
      <div class="settings-service-actions">
        <button type="submit" class="secondary-button settings-manage" disabled={!canCheck}>{working ? 'Checking…' : 'Check server'}</button>
      </div>
    </form>
  {/if}
</article>

<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import type { PcLinkEnrollment, PcLinkStatus } from '../types'
  import {
    cancelPcLinkPairing,
    confirmPcLinkPairing,
    getPcLinkStatus,
    grantPresence,
    PRESENCE_REQUIRED,
    rejectPcLinkPairing,
    revokePcLink,
    startPcLinkPairing,
  } from '../vault'

  let status: PcLinkStatus | null = null
  let loadError = ''
  let working = false
  let needsPresence = false
  let password = ''
  let pendingAction: (() => Promise<unknown>) | null = null
  let revoking = ''
  let poll: ReturnType<typeof setInterval> | null = null

  $: pairing = status?.pairing ?? null
  $: pendingEnrollments = pairing?.enrollments.filter((enrollment) => enrollment.state === 'pending_confirmation') ?? []
  $: finishingEnrollments = pairing?.enrollments.filter((enrollment) => enrollment.state === 'confirmed' || enrollment.state === 'pending_commit' || enrollment.state === 'active') ?? []
  $: terminalEnrollment = pairing?.enrollments.find((enrollment) => enrollment.state === 'rejected' || enrollment.state === 'expired')

  onMount(() => {
    void refresh()
  })

  onDestroy(() => {
    stopPolling()
  })

  function message(error: unknown): string {
    return error instanceof Error ? error.message : String(error)
  }

  function startPolling() {
    if (poll) return
    poll = setInterval(() => void refresh(), 1_500)
  }

  function stopPolling() {
    if (poll) clearInterval(poll)
    poll = null
  }

  async function refresh() {
    try {
      status = await getPcLinkStatus()
      loadError = ''
      if (status.pairing) startPolling()
      else stopPolling()
    } catch (error) {
      loadError = message(error)
      stopPolling()
    }
  }

  async function execute(action: () => Promise<unknown>) {
    working = true
    loadError = ''
    try {
      await action()
      needsPresence = false
      password = ''
      pendingAction = null
      await refresh()
    } catch (error) {
      if (message(error) === PRESENCE_REQUIRED) {
        needsPresence = true
        pendingAction = action
        loadError = 'Confirm your master password to continue.'
      } else {
        loadError = message(error)
      }
    } finally {
      working = false
    }
  }

  async function confirmPresence() {
    if (!password || working) return
    working = true
    loadError = ''
    try {
      await grantPresence(password)
      password = ''
      needsPresence = false
      const action = pendingAction
      pendingAction = null
      working = false
      if (action) await execute(action)
    } catch (error) {
      password = ''
      working = false
      loadError = message(error)
    }
  }

  function linkPhone() {
    void execute(startPcLinkPairing)
  }

  function approve(enrollment: PcLinkEnrollment) {
    void execute(() => confirmPcLinkPairing(enrollment.enrollmentId))
  }

  function reject(enrollment: PcLinkEnrollment) {
    void execute(() => rejectPcLinkPairing(enrollment.enrollmentId))
  }

  function cancel() {
    void execute(cancelPcLinkPairing)
  }

  function confirmRevoke(linkId: string) {
    if (revoking !== linkId) {
      revoking = linkId
      return
    }
    revoking = ''
    void execute(() => revokePcLink(linkId))
  }

  function formatTime(seconds: number): string {
    return new Date(seconds * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  }

  function stateLabel(state: PcLinkEnrollment['state']): string {
    switch (state) {
      case 'pending_confirmation':
        return 'Waiting for your approval'
      case 'confirmed':
        return 'Waiting for the phone'
      case 'pending_commit':
        return 'Finishing'
      case 'active':
        return 'Linked'
      case 'rejected':
        return 'Rejected'
      default:
        return 'Expired'
    }
  }
</script>

<article class="pc-link-summary">
  <div class="setting-copy">
    <strong>Phone link</strong>
    <p>Retrieve an encrypted copy from this PC on the same local network. Sesame must be running and this vault unlocked. The phone validates this PC's certificate before it sends anything.</p>
    {#if status?.desktopFingerprint}
      <p class="pc-link-meta">Desktop certificate <code class="pc-link-fingerprint">{status.desktopFingerprint}</code></p>
    {:else if status}
      <p class="pc-link-meta">PC link is not set up on this PC yet. Linking a phone creates its certificate identity.</p>
    {/if}
    {#if status?.retrievalPort !== null && status?.retrievalPort !== undefined}
      <p class="pc-link-meta">
        {#if status.discoveryHostname}
          Retrieval endpoint {status.discoveryHostname}:{status.retrievalPort}.
        {:else}
          Retrieval port {status.retrievalPort}.
        {/if}
        {#if status.discoveryAvailable}
          The phone can find this PC on the local network.
        {:else}
          Discovery is unavailable. Enter this PC's local address and port {status.retrievalPort} manually on the phone.
        {/if}
      </p>
    {/if}
    {#if loadError}<p class="pc-link-error" role="alert">{loadError}</p>{/if}
  </div>
  <div class="pc-link-actions">
    {#if pairing}
      <button type="button" class="secondary-button settings-manage" disabled={working} on:click={cancel}>
        Close pairing
      </button>
    {:else}
      <button type="button" class="secondary-button settings-manage" disabled={working} on:click={linkPhone}>
        {working ? 'Starting…' : 'Link phone'}
      </button>
    {/if}
  </div>
</article>

{#if needsPresence}
  <article class="pc-link-presence">
    <div class="setting-copy">
      <strong>Confirm your master password</strong>
      <p>Confirm your master password to open the short pairing window. Approve the phone before that confirmation expires.</p>
    </div>
    <form class="pc-link-presence-form" on:submit|preventDefault={confirmPresence}>
      <input bind:value={password} type="password" autocomplete="current-password" aria-label="Master password" placeholder="Master password" disabled={working} />
      <button type="submit" class="secondary-button settings-manage" disabled={working || !password}>Continue</button>
    </form>
  </article>
{/if}

{#if status?.links.length}
  <article>
    <div class="setting-copy">
      <strong>Linked phones</strong>
      <p>Revoking a phone stops new retrievals. A copy already received cannot be erased.</p>
      <ul class="pc-link-list">
        {#each status.links as link (link.linkId)}
          <li class="pc-link-entry">
            <div>
              <strong>{link.label || 'Unnamed phone'}</strong>
              <code class="pc-link-fingerprint">{link.phonePublicKeyFingerprint}</code>
              {#if link.notAfter * 1000 <= Date.now()}
                <p class="pc-link-meta">Expired. Pair the phone again.</p>
              {/if}
            </div>
            <button type="button" class="text-button" class:pc-link-revoke={revoking === link.linkId} disabled={working} on:click={() => confirmRevoke(link.linkId)}>
              {revoking === link.linkId ? 'Confirm revoke' : 'Revoke'}
            </button>
          </li>
        {/each}
      </ul>
    </div>
  </article>
{/if}

{#if pairing}
  <article>
    <div class="setting-copy">
      <strong>Pairing window open</strong>
      <p>On the phone, choose the PC and enter this code. Compare the desktop fingerprint before approving the phone.</p>
      <code class="pc-link-code">{pairing.code}</code>
      <p class="pc-link-meta">
        {#if status?.discoveryHostname}
          Pairing endpoint {status.discoveryHostname}:{pairing.port}.
        {:else}
          Pairing port {pairing.port}.
        {/if}
        For manual setup, use this PC's local IP address and port {pairing.port}. This code expires at {formatTime(pairing.expiresAt)}.
      </p>

      {#if pendingEnrollments.length}
        <div class="pc-link-enrollment">
          <strong>Check the phone before approving</strong>
          {#each pendingEnrollments as enrollment (enrollment.enrollmentId)}
            <div class="pc-link-entry">
              <div>
                <span>{enrollment.label || 'Unnamed phone'}</span>
                <code class="pc-link-fingerprint">{enrollment.phonePublicKeyFingerprint}</code>
              </div>
              <div class="pc-link-enrollment-actions">
                <button type="button" class="secondary-button settings-manage" disabled={working} on:click={() => approve(enrollment)}>Approve</button>
                <button type="button" class="text-button" disabled={working} on:click={() => reject(enrollment)}>Reject</button>
              </div>
            </div>
          {/each}
        </div>
      {:else if finishingEnrollments.length}
        <p class="pc-link-meta">
          {stateLabel(finishingEnrollments[0].state)}.
          {finishingEnrollments[0].state === 'active' ? 'You can close this window.' : 'Keep this window open until the phone finishes.'}
        </p>
      {:else if terminalEnrollment}
        <p class="pc-link-meta">{stateLabel(terminalEnrollment.state)}. Close pairing and choose Link phone to create a new code.</p>
      {:else}
        <p class="pc-link-meta">Waiting for a phone to enter the code.</p>
      {/if}
    </div>
  </article>
{/if}

<style>
  .pc-link-meta {
    margin: 0.35rem 0 0;
    color: var(--text-muted);
    font-size: var(--type-2);
  }

  .pc-link-fingerprint {
    display: block;
    margin-top: 0.2rem;
    color: var(--text-muted);
    font-family: var(--font-code);
    font-size: var(--type-1);
    line-height: 1.45;
    overflow-wrap: anywhere;
  }

  .pc-link-error {
    margin: 0.45rem 0 0;
    color: var(--danger);
    font-size: var(--type-2);
  }

  .pc-link-actions,
  .pc-link-enrollment-actions {
    display: flex;
    flex: none;
    align-items: center;
    gap: var(--space-2);
  }

  .pc-link-presence {
    align-items: center;
  }

  .pc-link-presence-form {
    display: flex;
    flex: none;
    min-width: 0;
    max-width: 100%;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }

  .pc-link-presence-form input {
    width: 13rem;
    min-width: 0;
    max-width: 100%;
    border: 1px solid var(--field-border);
    border-radius: var(--radius-sm);
    padding: var(--space-2) var(--space-3);
    color: var(--text);
    background: var(--field-bg);
    font-size: var(--type-3);
  }

  .pc-link-presence-form input:focus-visible {
    box-shadow: var(--field-ring);
    outline: none;
  }

  .pc-link-code {
    display: inline-block;
    margin-top: var(--space-2);
    color: var(--text);
    font-family: var(--font-code);
    font-size: var(--type-5);
    font-weight: var(--weight-bold);
    letter-spacing: 0.14em;
  }

  .pc-link-list {
    display: grid;
    gap: var(--space-2);
    margin: var(--space-2) 0 0;
    padding: 0;
    list-style: none;
  }

  .pc-link-entry {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-3);
    padding-top: var(--space-2);
    border-top: 1px solid var(--border-soft);
  }

  .pc-link-entry:first-child {
    padding-top: 0;
    border-top: 0;
  }

  .pc-link-enrollment {
    display: grid;
    gap: var(--space-2);
    margin-top: var(--space-3);
  }

  .pc-link-revoke {
    color: var(--danger);
  }
</style>

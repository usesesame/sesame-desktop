<script lang="ts">
  import { getContext, onDestroy, onMount } from 'svelte'
  import { messageFor } from '../controllers/feedback-controller'
  import { platformCapabilities } from '../platform'
  import { entryTime } from '../release-record'
  import { APP_STORES, type AppStores } from '../stores/app-stores'
  import {
    forgetTerminalPermissions,
    getTerminalStatus,
    listTerminalPermissions,
    onTerminalPermissionsChanged,
    onTerminalStatusChanged,
    type TerminalAllowanceList,
    type TerminalToolStatus,
  } from '../terminal-api'
  import { allowedRequestWords, remainingWords, shownText } from '../terminal-text'
  import { vaultItems } from '../vault-items'

  const stores = getContext<AppStores | undefined>(APP_STORES)
  const vault = stores?.vault

  let status: TerminalToolStatus | null = null
  let permissions: TerminalAllowanceList | null = null
  let permissionsFailed = false
  let fetchedAt = performance.now()
  let now = fetchedAt
  let working = false
  let errorMessage = ''
  let permissionsError = ''
  let permissionsRead = 0
  let statusEvents = 0
  let disposed = false
  const stops: Array<() => void> = []

  $: windows = $platformCapabilities.os === 'windows'
  $: snapshot = vault ? $vault?.snapshot ?? null : null
  $: items = vaultItems(snapshot)
  $: live = (permissions?.allowances ?? [])
    .map((allowance) => ({ ...allowance, left: allowance.expiresInMs - (now - fetchedAt) }))
    .filter((allowance) => allowance.left > 0)
  $: requests = permissions?.requests ?? []
  $: nothingToForget = permissions !== null && !permissionsFailed && live.length === 0 && requests.length === 0
  $: statusLabel = !status
    ? 'Checking…'
    : status.code === 'ready'
      ? 'Ready'
      : status.code === 'starting'
        ? 'Starting'
        : status.code === 'servedElsewhere'
          ? 'Used by another Sesame'
          : status.code === 'failed'
            ? 'Not running'
            : 'Not on this system'
  $: statusTone = status?.code === 'ready' ? '' : status?.code === 'servedElsewhere' || status?.code === 'failed' ? 'warning' : 'neutral'

  function description(current: TerminalToolStatus | null, onWindows: boolean): string {
    if (!current) return 'Checking the command line tool.'
    if (current.code === 'unsupported') return 'The command line tool does not work on this operating system.'
    if (current.code === 'servedElsewhere') return 'Another Sesame on this computer already answers the command line tool, so commands reach that one. Close the other Sesame and restart this one to use it here.'
    if (current.code === 'failed') return 'Sesame could not start listening for the command line tool. Restart Sesame to try again.'
    if (current.code === 'starting') return 'Sesame is getting ready to answer the command line tool.'
    if (onWindows) return 'Run sesame list, sesame get or sesame totp in a terminal, and Sesame asks in this window before it answers.'
    return 'Run sesame list, sesame get or sesame totp in a terminal, and Sesame asks in this window before it answers. A terminal you allowed is answered without asking, unless the request needs your master password or a choice between items.'
  }

  function titleFor(itemId: string | undefined): string | null {
    if (!itemId) return null
    const item = items.find((candidate) => candidate.id === itemId)
    return item ? shownText(item.title) : null
  }

  async function refreshPermissions() {
    const read = ++permissionsRead
    try {
      const next = await listTerminalPermissions()
      if (disposed || read !== permissionsRead) return
      permissions = next
      permissionsFailed = false
      permissionsError = ''
      fetchedAt = performance.now()
      now = fetchedAt
    } catch (error) {
      if (disposed || read !== permissionsRead) return
      permissionsError = messageFor(error)
      permissionsFailed = true
    }
  }

  function statusChanged(next: TerminalToolStatus) {
    statusEvents += 1
    status = next
  }

  async function refreshStatus() {
    const eventsBefore = statusEvents
    try {
      const next = await getTerminalStatus()
      if (!disposed && statusEvents === eventsBefore) status = next
    } catch (error) {
      if (!disposed) errorMessage = messageFor(error)
    }
  }

  async function forget() {
    if (working) return
    working = true
    errorMessage = ''
    permissionsRead += 1
    try {
      await forgetTerminalPermissions()
      await refreshPermissions()
    } catch (error) {
      errorMessage = messageFor(error)
    } finally {
      working = false
    }
  }

  function keep(stop: () => void) {
    if (disposed) stop()
    else stops.push(stop)
  }

  async function retry() {
    await refreshPermissions()
  }

  const ticker = window.setInterval(() => {
    now = performance.now()
    if (permissions?.allowances.some((allowance) => allowance.expiresInMs - (now - fetchedAt) <= 0)) void refreshPermissions()
  }, 1_000)

  onMount(() => {
    void onTerminalStatusChanged(statusChanged).then(keep).catch(() => {}).finally(() => void refreshStatus())
    void onTerminalPermissionsChanged(() => void refreshPermissions()).then(keep).catch(() => {}).finally(() => void refreshPermissions())
  })

  onDestroy(() => {
    disposed = true
    window.clearInterval(ticker)
    for (const stop of stops.splice(0)) stop()
  })
</script>

<div class="settings-list">
  <article>
    <div class="setting-copy">
      <strong>Command line tool</strong>
      <p>{description(status, windows)}</p>
      {#if windows && status?.supported}<p>On Windows, Sesame asks in this window every time a terminal makes a request.</p>{/if}
      {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
      {#if permissionsError}<p class="form-error" role="alert">{permissionsError}</p>{/if}
    </div>
    <span class="status-pill {statusTone}">{statusLabel}</span>
  </article>
  {#if !windows && status?.supported && (status.available || !nothingToForget)}
    <article class="terminal-setting-list">
      <div class="setting-copy">
        <strong>Allowed terminals</strong>
        {#if permissions === null}
          <p>{permissionsFailed ? 'Sesame could not read which terminals are allowed.' : 'Checking which terminals are allowed…'}</p>
        {:else if live.length}
          <ul aria-label="Allowed terminals">
            {#each live as allowance, index (index)}
              <li>
                <span class="terminal-line"><code><bdi>{shownText(allowance.terminal, 24)}</bdi></code>{#if allowance.remote}<span class="status-pill warning">Remote session</span>{/if}</span>
                <small>Allowed for {remainingWords(allowance.left)}</small>
                <span class="terminal-program">Covers this terminal and anything started from it.{#if allowance.program}&#32;The program that asked named itself <bdi>{shownText(allowance.program.reportedName, 48)}</bdi>.{/if}</span>
              </li>
            {/each}
          </ul>
        {:else}
          <p>{permissionsFailed ? 'Sesame could not read which terminals are allowed.' : 'No terminal is allowed right now, so every request asks.'}</p>
        {/if}
      </div>
    </article>
    <article class="terminal-setting-list">
      <div class="setting-copy">
        <strong>Answered without asking</strong>
        {#if permissions === null}
          <p>{permissionsFailed ? 'Sesame could not read the requests it answered.' : 'Checking the requests Sesame answered…'}</p>
        {:else if requests.length}
          <ul aria-label="Requests answered without asking">
            {#each requests as request, index (request.at + ':' + index)}
              <li>
                <span class="terminal-line"><bdi>{allowedRequestWords(request.command, request.field, titleFor(request.itemId), request.itemKind)}</bdi></span>
                <small><code><bdi>{shownText(request.terminal, 24)}</bdi></code> at {entryTime(request.at)}</small>
              </li>
            {/each}
          </ul>
        {:else}
          <p>None since Sesame was unlocked.</p>
        {/if}
      </div>
    </article>
    <article>
      <div class="setting-copy">
        <strong>Forget terminal permissions</strong>
        <p>Every allowed terminal asks again from its next request.</p>
      </div>
      <div class="terminal-actions">
        {#if permissionsFailed}<button type="button" class="secondary-button settings-manage" disabled={working} on:click={retry}>Try again</button>{/if}
        <button type="button" class="secondary-button settings-manage" disabled={working || nothingToForget} on:click={forget}>{working ? 'Forgetting…' : 'Forget'}</button>
      </div>
    </article>
  {/if}
</div>

<style>
  .terminal-setting-list ul { display: grid; margin: var(--space-2) 0 0; padding: 0; list-style: none; }
  .terminal-setting-list li { overflow: hidden; line-height: 1.7; display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: var(--space-1) var(--space-3); padding: var(--space-2) 0; }
  .terminal-setting-list li + li { border-top: 1px solid var(--border-soft); }
  .terminal-line { display: inline-flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-2); min-width: 0; color: var(--text); font-size: var(--type-3); overflow-wrap: anywhere; }
  .terminal-line code, .terminal-setting-list small code { font-family: var(--font-code); font-size: var(--type-2); }
  .terminal-program { flex-basis: 100%; min-width: 0; color: var(--text-muted); font-size: var(--type-2); overflow-wrap: anywhere; }
  .terminal-line .status-pill { margin-left: 0; }
  .terminal-setting-list small { color: var(--text-muted); font-size: var(--type-2); white-space: nowrap; }
  .terminal-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-2); }
  bdi { unicode-bidi: isolate; }
</style>

<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import Icon from '../Icon.svelte'
  import { copyToClipboard, listTotpCodes } from '../vault'
  import type { TotpCodeEntry } from '../types'

  export let onOpenImport: () => void
  export let reloadToken = 0

  $: void reloadFor(reloadToken)

  let codes: TotpCodeEntry[] = []
  let query = ''
  let loading = true
  let loadFailed = false
  let copiedId = ''
  let copiedTimer: number | undefined
  let ticker: number | undefined
  let refreshing = false
  let failures = 0
  let retryAt = 0
  let copyFailed = false

  $: filtered = filterCodes(codes, query)

  function filterCodes(all: TotpCodeEntry[], search: string): TotpCodeEntry[] {
    const needle = search.trim().toLowerCase()
    if (!needle) return all
    return all.filter((code) =>
      code.title.toLowerCase().includes(needle) || code.site.toLowerCase().includes(needle))
  }

  // Guarded and backed off: a failure leaves every code at zero, which would
  // otherwise ask for a fresh read every second for as long as the view is open.
  async function load() {
    if (refreshing || Date.now() < retryAt) return
    refreshing = true
    try {
      codes = await listTotpCodes()
      loadFailed = false
      failures = 0
      retryAt = 0
    } catch {
      failures += 1
      retryAt = Date.now() + (failures >= 3 ? 5_000 : 1_500)
      loadFailed = true
    } finally {
      refreshing = false
      loading = false
    }
  }

  // Codes are derived in Rust, so the window is authoritative there. Count down
  // locally and re-read once the shortest one runs out.
  function tick() {
    if (!codes.length) {
      if (loadFailed) void load()
      return
    }
    let expired = false
    codes = codes.map((code) => {
      const remaining = code.remaining - 1
      if (remaining <= 0) expired = true
      return { ...code, remaining: Math.max(0, remaining) }
    })
    if (expired) void load()
  }

  async function copy(code: TotpCodeEntry) {
    try {
      await copyToClipboard(code.code)
    } catch {
      copyFailed = true
      return
    }
    copyFailed = false
    copiedId = code.id
    if (copiedTimer) window.clearTimeout(copiedTimer)
    copiedTimer = window.setTimeout(() => (copiedId = ''), 1_500)
  }

  // Re-read on demand, so the toolbar Refresh reaches this view too.
  let lastReloadToken = -1
  async function reloadFor(token: number) {
    if (token === lastReloadToken) return
    lastReloadToken = token
    if (token > 0) await load()
  }

  onMount(() => {
    void load()
    ticker = window.setInterval(tick, 1_000)
  })
  onDestroy(() => {
    if (ticker) window.clearInterval(ticker)
    if (copiedTimer) window.clearTimeout(copiedTimer)
  })
</script>

<header class="view-header">
  <div>
    <!-- A failed read knows nothing about the count, so it must not claim zero. -->
    <h2>{loading || loadFailed ? 'Authenticator' : codes.length === 1 ? '1 code saved' : `${codes.length} codes saved`}</h2>
  </div>
</header>

{#if loading}
  <p class="authenticator-status" role="status">Reading your codes…</p>
{:else if loadFailed}
  <p class="authenticator-status" role="alert">Sesame could not read your codes. It keeps trying, and Refresh retries now.</p>
{:else if !codes.length}
  <div class="authenticator-empty">
    <span class="authenticator-empty-icon"><Icon name="shield" size={22} /></span>
    <h2>No two-factor codes saved yet</h2>
    <p>Add a code to a login, or bring your codes over from an authenticator app.</p>
    <button type="button" class="primary-button" on:click={onOpenImport}>Import codes</button>
  </div>
{:else}
  <label class="authenticator-search">
    <Icon name="search" size={16} />
    <input type="search" bind:value={query} placeholder="Search codes" autocomplete="off" spellcheck="false" />
  </label>

  {#if copyFailed}
    <p class="authenticator-status" role="alert">Sesame could not copy that code to the clipboard. Try again.</p>
  {/if}
  {#if !filtered.length}
    <p class="authenticator-status">No code matches that search.</p>
  {:else}
    <ul class="authenticator-list">
      {#each filtered as code (code.id)}
        <li>
          <button type="button" class="authenticator-row" on:click={() => void copy(code)}>
            <span class="entry-avatar" aria-hidden="true">{code.initials}</span>
            <span class="authenticator-names">
              <strong>{code.title}</strong>
              {#if code.site}<small>{code.site}</small>{/if}
            </span>
            <span class="authenticator-code" class:expiring={code.remaining <= 5}>{code.code}</span>
            <span class="authenticator-remaining" aria-label={`${code.remaining} seconds left`}>
              {copiedId === code.id ? 'Copied' : `${code.remaining}s`}
            </span>
          </button>
        </li>
      {/each}
    </ul>
  {/if}
{/if}

<style>
  .authenticator-status { margin: var(--space-5) 0 0; color: var(--text-muted); font-size: var(--type-2); }
  .authenticator-search {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    max-width: 24rem;
    margin-top: var(--space-5);
    border-radius: var(--radius-md);
    padding: 0 var(--space-3);
    color: var(--text-muted);
    background: var(--surface-inset);
  }
  .authenticator-search input {
    flex: 1;
    min-width: 0;
    border: 0;
    padding: 11px 0;
    background: transparent;
    color: var(--text);
    font-size: var(--type-2);
  }
  .authenticator-search input:focus { outline: none; }
  .authenticator-list {
    display: grid;
    gap: var(--space-2);
    max-width: 40rem;
    margin: var(--space-4) 0 0;
    padding: 0;
    list-style: none;
  }
  .authenticator-row {
    display: grid;
    grid-template-columns: 32px minmax(0, 1fr) auto auto;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-md);
    padding: var(--space-3);
    background: var(--surface);
    color: var(--text);
    text-align: left;
    cursor: pointer;
    transition: background var(--t-fast) ease;
  }
  .authenticator-row:hover { background: var(--surface-3); }
  .authenticator-names { display: grid; gap: 2px; min-width: 0; }
  .authenticator-names strong { overflow: hidden; font-size: var(--type-2); text-overflow: ellipsis; white-space: nowrap; }
  .authenticator-names small { overflow: hidden; color: var(--text-muted); font-size: var(--type-1); text-overflow: ellipsis; white-space: nowrap; }
  .authenticator-code {
    font-family: var(--font-code);
    font-size: var(--type-4);
    font-variant-numeric: tabular-nums;
    letter-spacing: .12em;
  }
  .authenticator-code.expiring { color: var(--warn-text); }
  .authenticator-remaining {
    min-width: 3.5rem;
    color: var(--text-muted);
    font-size: var(--type-1);
    font-variant-numeric: tabular-nums;
    text-align: right;
  }
  .authenticator-empty {
    display: grid;
    justify-items: center;
    gap: var(--space-3);
    max-width: 26rem;
    margin: var(--space-6) auto 0;
    text-align: center;
  }
  .authenticator-empty-icon {
    display: grid;
    place-items: center;
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    color: var(--chip-icon);
    background: var(--chip-bg);
  }
  .authenticator-empty h2 { margin: 0; color: var(--text-heading); font-size: var(--type-4); }
  .authenticator-empty p { margin: 0; color: var(--text-muted); font-size: var(--type-2); line-height: 1.5; }
</style>

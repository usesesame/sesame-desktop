<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import Icon from '../Icon.svelte'
  import ViewHeader from './ViewHeader.svelte'
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
  let now = Date.now()
  let expiryAt: number[] = []

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
      now = Date.now()
      expiryAt = codes.map((code) => now + code.remaining * 1_000)
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

  // Rust owns the window, so each code is pinned to an absolute expiry and the
  // sweep is interpolated against the clock. That stays true if a frame is late.
  function tick() {
    now = Date.now()
    if (!codes.length) {
      if (loadFailed) void load()
      return
    }
    if (expiryAt.some((expiry) => expiry <= now)) void load()
  }

  function secondsLeft(index: number, at: number): number {
    return Math.max(0, Math.ceil((expiryAt[index] - at) / 1_000))
  }

  function sweep(code: TotpCodeEntry, index: number, at: number): number {
    const window = Math.max(1, code.period) * 1_000
    return Math.min(1, Math.max(0, (expiryAt[index] - at) / window))
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
    ticker = window.setInterval(tick, 100)
  })
  onDestroy(() => {
    if (ticker) window.clearInterval(ticker)
    if (copiedTimer) window.clearTimeout(copiedTimer)
  })
</script>

<section class="authenticator-view">
<ViewHeader title="Authenticator" />
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
  <section class="authenticator-card">
    <label class="search-box authenticator-search">
      <Icon name="search" size={16} />
      <input name="authenticator-search" type="search" bind:value={query} placeholder="Search codes…" aria-label="Search authenticator codes" autocomplete="off" spellcheck="false" />
    </label>

    {#if copyFailed}
      <p class="authenticator-status" role="alert">Sesame could not copy that code to the clipboard. Try again.</p>
    {/if}
    {#if !filtered.length}
      <p class="authenticator-status">No code matches that search.</p>
    {:else}
      <ul class="authenticator-list">
        {#each filtered as code (code.id)}
          {@const index = codes.indexOf(code)}
          {@const left = secondsLeft(index, now)}
          <li>
            <button type="button" class="authenticator-row" on:click={() => void copy(code)}>
              <span class="entry-avatar" aria-hidden="true">{code.initials}</span>
              <span class="authenticator-names">
                <strong>{code.title}</strong>
                {#if code.site}<small>{code.site}</small>{/if}
              </span>
              <span class="authenticator-code" class:expiring={left <= 5}>{code.code}</span>
              {#if copiedId === code.id}
                <span class="authenticator-copied">Copied</span>
              {:else}
                <span
                  class="code-countdown"
                  class:expiring={left <= 5}
                  style={`--totp-progress: ${sweep(code, index, now) * 100}%`}
                  role="img"
                  aria-label={`${left} seconds left`}
                ><small>{left}</small></span>
              {/if}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{/if}
</section>

<style>
  .authenticator-status { margin: var(--space-3) 0 0; color: var(--text-muted); font-size: var(--type-2); }
  /* The card matches the vault list panel: surface container, inset search, hover rows. */
  .authenticator-card { margin: var(--space-4) 0 0; padding: var(--space-4); border-radius: var(--radius-lg); background: var(--surface); box-shadow: var(--shadow-raised); }
  .authenticator-search { margin-top: 0; padding: 0 var(--space-2); }
  .authenticator-list {
    display: grid;
    gap: 2px;
    margin: var(--space-3) 0 0;
    padding: 0;
    list-style: none;
  }
  .authenticator-row {
    display: grid;
    grid-template-columns: 32px minmax(0, 1fr) auto 2.5rem;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    border: 0;
    border-radius: var(--radius-md);
    padding: var(--space-2) var(--space-3);
    background: transparent;
    color: var(--text);
    text-align: left;
    cursor: pointer;
    transition: background var(--t-fast) ease;
  }
  .authenticator-row:hover { background: var(--control-hover); }
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
  .authenticator-copied {
    min-width: 2.5rem;
    color: var(--ok-text);
    font-size: var(--type-1);
    font-weight: 600;
    text-align: right;
  }
  /* The same ring the login detail uses, swept continuously rather than per second. */
  .code-countdown {
    position: relative;
    display: grid;
    width: 2.5rem;
    height: 2.5rem;
    place-items: center;
    border-radius: 50%;
    background: conic-gradient(var(--gold-text-soft) var(--totp-progress), var(--gold-border) 0);
  }
  .code-countdown::before {
    position: absolute;
    inset: 3px;
    border-radius: inherit;
    background: var(--surface);
    content: '';
  }
  .code-countdown small {
    position: relative;
    color: var(--gold-text);
    font-size: var(--type-1);
    font-weight: 700;
    font-variant-numeric: tabular-nums;
  }
  .code-countdown.expiring {
    background: conic-gradient(var(--warn-text) var(--totp-progress), var(--gold-border) 0);
  }
  .code-countdown.expiring small { color: var(--warn-text); }
  /* The disc sits on the row, so it follows the row rather than staying behind. */
  .authenticator-row:hover .code-countdown::before { background: color-mix(in srgb, var(--text) 4%, var(--surface)); }
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

<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte'
  import { getCurrentWindow } from '@tauri-apps/api/window'
  import Icon from '../Icon.svelte'
  import WebsiteIcon from './WebsiteIcon.svelte'
  import { readSiteIcons } from '../preferences'
  import { copyToClipboard, getQuickAccessSecret, getQuickAccessStatus, previewMode, searchQuickAccessEntries } from '../vault'
  import type { QuickAccessEntry } from '../types'

  type Stage = 'loading' | 'locked' | 'ready' | 'unavailable'

  let stage: Stage = 'loading'
  let entries: QuickAccessEntry[] = []
  let query = ''
  let selectedIndex = 0
  let copyingId = ''
  let copiedId = ''
  let copiedField: 'password' | 'totp' | '' = ''
  let searchInput: HTMLInputElement | undefined
  let searchSequence = 0
  let siteIconsEnabled = readSiteIcons()

  $: if (selectedIndex >= entries.length) selectedIndex = Math.max(0, entries.length - 1)

  function closeWindow() {
    if (!previewMode) void getCurrentWindow().hide()
  }

  function resetTransientState() {
    query = ''
    selectedIndex = 0
    copyingId = ''
    copiedId = ''
    copiedField = ''
  }

  async function updateSearch() {
    const sequence = ++searchSequence
    try {
      const next = await searchQuickAccessEntries(query)
      if (sequence !== searchSequence) return
      entries = next
      selectedIndex = 0
    } catch {
      if (sequence === searchSequence) stage = 'locked'
    }
  }

  async function refresh() {
    siteIconsEnabled = readSiteIcons()
    try {
      const status = await getQuickAccessStatus()
      if (!status.exists) {
        stage = 'unavailable'
        return
      }
      if (!status.unlocked) {
        stage = 'locked'
        return
      }
      stage = 'ready'
      await updateSearch()
      await tick()
      searchInput?.focus()
    } catch {
      stage = 'unavailable'
    }
  }

  async function copyEntry(entry: QuickAccessEntry, field: 'password' | 'totp' = 'password') {
    if (copyingId) return
    copyingId = entry.id
    try {
      const secret = await getQuickAccessSecret(entry.id)
      const value = field === 'totp' ? secret.totpCode : secret.password
      if (!value) {
        copyingId = ''
        return
      }
      await copyToClipboard(value)
      copiedId = entry.id
      copiedField = field
      window.setTimeout(closeWindow, 550)
    } catch {
      copyingId = ''
    }
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault()
      closeWindow()
      return
    }
    if (stage !== 'ready') return
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      selectedIndex = Math.min(entries.length - 1, selectedIndex + 1)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      selectedIndex = Math.max(0, selectedIndex - 1)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      const entry = entries[selectedIndex]
      if (!entry) return
      if (event.shiftKey && entry.hasTotp) void copyEntry(entry, 'totp')
      else void copyEntry(entry)
    }
  }

  let stopFocusListener: (() => void) | undefined
  onMount(() => {
    void refresh()
    if (!previewMode) {
      void getCurrentWindow()
        .onFocusChanged(({ payload: focused }) => {
          if (focused) {
            resetTransientState()
            void refresh()
          }
        })
        .then((stop) => {
          stopFocusListener = stop
        })
    }
  })
  onDestroy(() => stopFocusListener?.())
</script>

<svelte:window on:keydown={onKeydown} />

<div class="quick-access">
  {#if stage === 'loading'}
    <div class="quick-access-status"><span class="inline-spinner" aria-hidden="true"></span><p>Checking the vault…</p></div>
  {:else if stage === 'unavailable'}
    <div class="quick-access-status"><Icon name="alert" size={18} /><p>Sesame is not set up on this device yet.</p></div>
  {:else if stage === 'locked'}
    <div class="quick-access-status"><Icon name="lock" size={18} /><p>Unlock your vault in the main Sesame window.</p></div>
  {:else}
    <label class="quick-access-search">
      <Icon name="search" size={16} />
      <input bind:this={searchInput} bind:value={query} on:input={() => void updateSearch()} type="text" autocomplete="off" spellcheck="false" placeholder="Search Sesame" />
    </label>
    {#if entries.length}
      <ul class="quick-access-results">
        {#each entries as entry, index (entry.id)}
          <li class="quick-access-result-row">
            <button type="button" class:active={index === selectedIndex} on:mouseenter={() => (selectedIndex = index)} on:click={() => copyEntry(entry)} disabled={Boolean(copyingId) && copyingId !== entry.id}>
              <span class="entry-avatar" aria-hidden="true"><WebsiteIcon site={entry.site} initials={entry.initials} enabled={siteIconsEnabled} /></span>
              <span class="quick-access-result-copy"><strong>{entry.title}</strong><small>{entry.site}</small></span>
              <span class="quick-access-result-state">{copiedId === entry.id ? (copiedField === 'totp' ? 'Code copied' : 'Copied') : copyingId === entry.id ? 'Copying…' : 'Copy password'}</span>
            </button>
            {#if entry.hasTotp}
              <button
                type="button"
                class="icon-button quick-access-totp-button"
                aria-label={`Copy the current 2FA code for ${entry.title}`}
                title="Copy 2FA code (Shift+Enter)"
                disabled={Boolean(copyingId) && copyingId !== entry.id}
                on:mouseenter={() => (selectedIndex = index)}
                on:click|stopPropagation={() => copyEntry(entry, 'totp')}
              >
                <Icon name="shield" size={14} />
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      <p class="quick-access-empty">{query.trim() ? 'No saved login matches.' : 'No logins saved yet.'}</p>
    {/if}
  {/if}
</div>

<style>
  :global(body) { min-width: 0; background: transparent; }
  .quick-access { display: flex; flex-direction: column; box-sizing: border-box; width: 100%; height: 100vh; padding: var(--space-3); border-radius: var(--radius-lg); background: var(--surface); box-shadow: var(--shadow-raise), var(--shadow-panel); overflow: hidden; }
  .quick-access-status { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: var(--space-3); flex: 1; color: var(--text-muted); font-size: var(--type-2); text-align: center; }
  .quick-access-search { display: flex; align-items: center; gap: var(--space-2); flex: none; border-radius: var(--radius-md); padding: 0 var(--space-3); color: var(--text-muted); background: var(--surface-inset); }
  .quick-access-search input { flex: 1; min-width: 0; border: 0; background: transparent; padding: 12px 0; color: var(--text); font-size: var(--type-3); }
  .quick-access-search input:focus { box-shadow: none; }
  .quick-access-results { display: flex; flex-direction: column; gap: 2px; margin: var(--space-2) 0 0; padding: 0; list-style: none; overflow-y: auto; }
  .quick-access-result-row { display: flex; align-items: center; gap: 2px; }
  .quick-access-result-row > button:first-child { display: flex; width: 100%; align-items: center; gap: var(--space-2); border: 0; border-radius: var(--radius-sm); padding: var(--space-2); color: var(--text); background: transparent; text-align: left; cursor: pointer; }
  .quick-access-result-row > button:first-child.active, .quick-access-result-row > button:first-child:hover:not(:disabled) { background: var(--tint); }
  .quick-access-result-row > button:first-child:disabled { cursor: default; opacity: .7; }
  .quick-access-totp-button { flex: none; }
  .quick-access-result-copy { display: flex; flex-direction: column; min-width: 0; flex: 1; }
  .quick-access-result-copy strong { overflow: hidden; font-size: var(--type-2); text-overflow: ellipsis; white-space: nowrap; }
  .quick-access-result-copy small { overflow: hidden; color: var(--text-muted); font-size: var(--type-1); text-overflow: ellipsis; white-space: nowrap; }
  .quick-access-result-state { flex: none; color: var(--text-faint); font-size: 11px; font-weight: 600; }
  .quick-access-empty { margin: var(--space-4) 0 0; color: var(--text-muted); font-size: var(--type-1); text-align: center; }
</style>

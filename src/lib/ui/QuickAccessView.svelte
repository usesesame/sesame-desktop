<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte'
  import { getCurrentWindow } from '@tauri-apps/api/window'
  import Icon from '../Icon.svelte'
  import WebsiteIcon from './WebsiteIcon.svelte'
  import { readSiteIcons } from '../preferences'
  import { copyToClipboard, getQuickAccessField, getQuickAccessStatus, openQuickAccessItem, previewMode, searchQuickAccessItems } from '../vault'
  import type { QuickAccessAction, QuickAccessItem } from '../types'
  import { itemKindIcon, itemKindLabel } from '../vault-items'

  type Stage = 'loading' | 'locked' | 'ready' | 'unavailable'

  let stage: Stage = 'loading'
  let items: QuickAccessItem[] = []
  let query = ''
  let selectedIndex = 0
  let workingId = ''
  let doneId = ''
  let doneLabel = ''
  let confirming: { id: string; field: string } | null = null
  let searchInput: HTMLInputElement | undefined
  let searchSequence = 0
  let siteIconsEnabled = readSiteIcons()

  $: if (selectedIndex >= items.length) selectedIndex = Math.max(0, items.length - 1)

  function closeWindow() {
    if (!previewMode) void getCurrentWindow().hide()
  }

  function resetTransientState() {
    query = ''
    selectedIndex = 0
    workingId = ''
    doneId = ''
    doneLabel = ''
    confirming = null
  }

  async function updateSearch() {
    const sequence = ++searchSequence
    try {
      const next = await searchQuickAccessItems(query)
      if (sequence !== searchSequence) return
      items = next
      selectedIndex = 0
      confirming = null
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

  async function runAction(item: QuickAccessItem, action: QuickAccessAction) {
    if (workingId) return
    if (action.field === 'open') {
      workingId = item.id
      try {
        await openQuickAccessItem(item.id)
      } catch {
        workingId = ''
      }
      return
    }
    if (action.guarded && confirming?.field !== action.field) {
      confirming = { id: item.id, field: action.field }
      return
    }
    workingId = item.id
    try {
      const { value } = await getQuickAccessField(item.id, action.field, action.guarded)
      if (!value) {
        workingId = ''
        return
      }
      await copyToClipboard(value)
      doneId = item.id
      doneLabel = action.label.replace(/^Copy /, '')
      confirming = null
      window.setTimeout(closeWindow, 550)
    } catch {
      workingId = ''
    }
  }

  function primaryAction(item: QuickAccessItem): QuickAccessAction | undefined {
    return item.actions.find((action) => !action.guarded) ?? item.actions[0]
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault()
      if (confirming) {
        confirming = null
        return
      }
      closeWindow()
      return
    }
    if (stage !== 'ready') return
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      selectedIndex = Math.min(items.length - 1, selectedIndex + 1)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      selectedIndex = Math.max(0, selectedIndex - 1)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      const item = items[selectedIndex]
      if (!item) return
      const action = event.shiftKey ? item.actions[1] ?? primaryAction(item) : primaryAction(item)
      if (action) void runAction(item, action)
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
    {#if items.length}
      <ul class="quick-access-results">
        {#each items as item, index (item.id)}
          <li class="quick-access-result-row" class:active={index === selectedIndex}>
            <button type="button" class:active={index === selectedIndex} on:mouseenter={() => (selectedIndex = index)} on:click={() => { const action = primaryAction(item); if (action) void runAction(item, action) }} disabled={Boolean(workingId) && workingId !== item.id}>
              <span class="entry-avatar" aria-hidden="true">
                {#if item.kind === 'login'}<WebsiteIcon site={item.subtitle} initials={item.initials} enabled={siteIconsEnabled} />{:else}<Icon name={itemKindIcon(item.kind)} size={15} />{/if}
              </span>
              <span class="quick-access-result-copy"><strong>{item.title}</strong><small>{item.subtitle || itemKindLabel(item.kind)}</small></span>
              <span class="quick-access-result-state">{#if doneId === item.id}{doneLabel} copied{:else if workingId === item.id}Working…{:else}<Icon name="copy" size={13} />{primaryAction(item)?.label ?? 'No action'}{/if}</span>
            </button>
            <span class="quick-access-actions">
            {#each item.actions.slice(1) as action (action.field)}
              <button
                type="button"
                class="quick-access-action-button"
                class:confirming={confirming?.id === item.id && confirming?.field === action.field}
                aria-label={confirming?.id === item.id && confirming?.field === action.field ? `Confirm: ${action.label.toLowerCase()} for ${item.title}` : `${action.label} for ${item.title}`}
                title={confirming?.id === item.id && confirming?.field === action.field ? 'Select again to confirm' : action.label}
                disabled={Boolean(workingId) && workingId !== item.id}
                on:mouseenter={() => (selectedIndex = index)}
                on:click|stopPropagation={() => void runAction(item, action)}
              >
                <Icon name={action.guarded ? 'shield-alert' : 'copy'} size={14} />
                <span>{confirming?.id === item.id && confirming?.field === action.field ? 'Confirm' : action.label.replace(/^Copy /, '')}</span>
              </button>
            {/each}
            </span>
          </li>
        {/each}
      </ul>
      {#if confirming}
        <p class="quick-access-confirm" role="status">Select that action again to copy the protected value.</p>
      {/if}
    {:else}
      <p class="quick-access-empty">{query.trim() ? 'No saved item matches.' : 'Nothing saved yet.'}</p>
    {/if}
  {/if}
</div>

<style>
  :global(body) { min-width: 0; background: transparent; }
  .quick-access { animation: view-enter .16s cubic-bezier(.2, .7, .2, 1) both; display: flex; flex-direction: column; box-sizing: border-box; width: 100%; height: 100vh; padding: var(--space-3); border-radius: var(--radius-lg); background: var(--surface); box-shadow: var(--shadow-raise), var(--shadow-panel); overflow: hidden; }
  .quick-access-status { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: var(--space-3); flex: 1; color: var(--text-muted); font-size: var(--type-2); text-align: center; }
  .quick-access-search { display: flex; align-items: center; gap: var(--space-2); flex: none; border-radius: var(--radius-md); padding: 0 var(--space-3); color: var(--text-muted); background: var(--surface-inset); }
  .quick-access-search input { flex: 1; min-width: 0; border: 0; background: transparent; padding: 12px 0; color: var(--text); font-size: var(--type-3); }
  .quick-access-search input:focus { box-shadow: none; }
  .quick-access-results { display: flex; flex-direction: column; gap: 2px; margin: var(--space-2) 0 0; padding: 0 var(--space-1) 0 0; list-style: none; overflow-y: auto; scrollbar-gutter: stable; }
  .quick-access-result-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; min-width: 0; align-items: center; gap: var(--space-1); }
  .quick-access-result-row > button:first-child { display: grid; grid-template-columns: 32px minmax(0, 1fr) auto; min-width: 0; align-items: center; gap: var(--space-2); border: 0; border-radius: var(--radius-sm); padding: var(--space-2); color: var(--text); background: transparent; text-align: left; cursor: pointer; }
  .quick-access-actions { display: flex; align-items: center; justify-content: flex-end; gap: var(--space-1); }
  .quick-access-result-row:not(.active) .quick-access-actions,
  .quick-access-result-row:not(.active) .quick-access-result-state { display: none; }
  .quick-access-result-row > button:first-child.active, .quick-access-result-row > button:first-child:hover:not(:disabled) { background: var(--tint); }
  .quick-access-result-row > button:first-child:disabled { cursor: default; opacity: .7; }
  .quick-access-action-button { display: inline-flex; min-height: 32px; flex: none; align-items: center; gap: 6px; border: 0; border-radius: var(--radius-sm); padding: 0 var(--space-2); color: var(--accent-link); background: var(--surface-inset); font-size: var(--type-1); font-weight: 650; white-space: nowrap; cursor: pointer; }
  .quick-access-action-button:hover:not(:disabled) { background: var(--tint); }
  .quick-access-action-button.confirming { color: var(--danger); background: var(--danger-bg); }
  .quick-access-action-button:disabled { cursor: default; opacity: .6; }
  .quick-access-result-copy { display: flex; flex-direction: column; min-width: 0; flex: 1; }
  .quick-access-result-copy strong { overflow: hidden; font-size: var(--type-2); text-overflow: ellipsis; white-space: nowrap; }
  .quick-access-result-copy small { overflow: hidden; color: var(--text-muted); font-size: var(--type-1); text-overflow: ellipsis; white-space: nowrap; }
  .quick-access-result-state { display: inline-flex; align-items: center; justify-self: end; gap: 5px; color: var(--text-faint); font-size: 11px; font-weight: 600; white-space: nowrap; }
  .quick-access-empty { margin: var(--space-4) 0 0; color: var(--text-muted); font-size: var(--type-1); text-align: center; }
  .quick-access-confirm { margin: var(--space-2) 0 0; padding: 0 var(--space-2); color: var(--text-faint); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .quick-access-confirm { color: var(--danger); }
</style>

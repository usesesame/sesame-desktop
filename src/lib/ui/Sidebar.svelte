<script lang="ts">
  import Icon from '../Icon.svelte'
  import { appChannel, appVersion } from '../app-meta'
  import type { NavigationGroup, View } from '../types'

  export let navigation: NavigationGroup[]
  export let activeView: View
  export let preview = false
  export let autoLockMinutes = 5
  export let onNavigate: (id: View) => void
  export let onLock: () => void
</script>

<aside class="sidebar">
  <div class="brand"><img class="sesame-mark" src="/favicon.svg" alt="" width="512" height="512" /><span>Sesame</span></div>
  <nav aria-label="Primary navigation">
    {#each navigation as group (group.items[0]?.id)}
      <div class="nav-group" class:utility={!group.label}>
        {#if group.label}<p class="nav-label">{group.label}</p>{/if}
        {#each group.items as item (item.id)}
          <button type="button" class:active={activeView === item.id} aria-current={activeView === item.id ? 'page' : undefined} aria-label={item.label} title={item.label} on:click={() => onNavigate(item.id)}>
            <span class="nav-icon" aria-hidden="true"><Icon name={item.icon} size={16} strokeWidth={1.9} /></span>
            <span class="nav-text">{item.label}</span>
          </button>
        {/each}
      </div>
    {/each}
  </nav>
  <div class="sidebar-bottom">
    <button type="button" class="lock-button" aria-label="Lock vault" title="Lock vault" on:click={onLock}><span class="nav-icon" aria-hidden="true"><Icon name="lock" size={15} /></span><span class="nav-text">Lock vault</span></button>
    <div class="sidebar-footer">
      <div class="sidebar-status">
        <p><span class="status-dot" aria-hidden="true"></span>{preview ? 'Preview mode' : 'Local vault'}</p>
        <p>Auto-lock after {autoLockMinutes} min</p>
      </div>
      <p class="sidebar-build" aria-label={$appVersion ? `Sesame desktop version ${$appVersion}${$appChannel ? `, ${$appChannel}` : ''}` : 'Sesame desktop version loading'}><span>Sesame desktop</span><span>{$appVersion ? `v${$appVersion}` : 'Version loading'}{$appChannel ? ` · ${$appChannel}` : ''}</span></p>
    </div>
  </div>
</aside>

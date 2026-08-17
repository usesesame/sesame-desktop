<script lang="ts">
  import Icon from '../Icon.svelte'
  import { APP_CHANNEL, appVersion } from '../app-meta'

  export let navigation: Array<{ id: string; label: string; icon: string }>
  export let activeView: string
  export let preview = false
  export let autoLockMinutes = 5
  export let onNavigate: (id: string) => void
  export let onLock: () => void
</script>

<aside class="sidebar">
  <div class="brand"><img class="sesame-mark" src="/favicon.svg" alt="" /><span>Sesame</span></div>
  <nav aria-label="Primary navigation">
    <p class="nav-label">Menu</p>
    {#each navigation as item (item.id)}
      <button type="button" class:active={activeView === item.id} aria-current={activeView === item.id ? 'page' : undefined} on:click={() => onNavigate(item.id)}>
        <span class="nav-icon" aria-hidden="true"><Icon name={item.icon} size={16} strokeWidth={1.9} /></span>
        {item.label}
      </button>
    {/each}
  </nav>
  <div class="sidebar-bottom">
    <button type="button" class="lock-button" on:click={onLock}><span class="nav-icon"><Icon name="lock" size={15} /></span> Lock vault</button>
    <p class="sidebar-status"><span class="status-dot" aria-hidden="true"></span>{preview ? 'Preview mode' : 'Local vault'} · <span>{autoLockMinutes}m auto-lock</span></p>
    <p class="sidebar-build" aria-label={$appVersion ? `Sesame desktop version ${$appVersion}, ${APP_CHANNEL}` : 'Sesame desktop version loading'}><span>Sesame desktop</span><span>{$appVersion ? `v${$appVersion}` : 'Version loading'} · {APP_CHANNEL}</span></p>
  </div>
</aside>

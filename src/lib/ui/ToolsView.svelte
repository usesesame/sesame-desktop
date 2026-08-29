<script lang="ts">
  import { tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import GeneratorView from './GeneratorView.svelte'
  import PassphraseGeneratorView from './PassphraseGeneratorView.svelte'
  import PasswordStrengthView from './PasswordStrengthView.svelte'
  import ViewHeader from './ViewHeader.svelte'

  export let onCopy: (value: string, label: string) => void
  export let onUseInLogin: (password: string) => void

  const { generator, passphrase, recentGenerations } = useAppStores()

  type ToolTabId = 'password' | 'passphrase' | 'strength'
  const tabs: { id: ToolTabId; label: string; icon: string }[] = [
    { id: 'password', label: 'Password', icon: 'key' },
    { id: 'passphrase', label: 'Passphrase', icon: 'file-key' },
    { id: 'strength', label: 'Strength checker', icon: 'shield-alert' },
  ]
  export let tab: ToolTabId = 'password'
  const tabButtons: HTMLButtonElement[] = []

  async function handleTabKeydown(event: KeyboardEvent, index: number) {
    let nextIndex: number | null = null
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % tabs.length
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + tabs.length) % tabs.length
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = tabs.length - 1
    if (nextIndex === null) return

    event.preventDefault()
    tab = tabs[nextIndex].id
    await tick()
    tabButtons[nextIndex]?.focus()
  }

  let lastPassword = ''
  let lastPassphrase = ''
  $: if ($generator.password && $generator.password !== lastPassword) {
    lastPassword = $generator.password
    recentGenerations.push({ value: $generator.password, kind: 'password' })
  }
  $: if ($passphrase.passphrase && $passphrase.passphrase !== lastPassphrase) {
    lastPassphrase = $passphrase.passphrase
    recentGenerations.push({ value: $passphrase.passphrase, kind: 'passphrase' })
  }
</script>

<section class="tools-view">
  <ViewHeader title="Password tools" />
  {#if $recentGenerations.items.length > 0}
    <section class="recent-generations" aria-label="Recently generated">
      <h3>Recent</h3>
      <ul>
        {#each $recentGenerations.items as item, index (index)}
          <li>
            <code>{item.value}</code>
            <button type="button" class="icon-button" aria-label={`Copy ${item.kind === 'password' ? 'password' : 'passphrase'}`} on:click={() => onCopy(item.value, item.kind === 'password' ? 'Password' : 'Passphrase')}><Icon name="copy" size={14} /></button>
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <div class="settings-tabs" role="tablist" aria-label="Tools">
    {#each tabs as item, index (item.id)}
      <button
        bind:this={tabButtons[index]}
        id={`tools-tab-${item.id}`}
        role="tab"
        type="button"
        class:active={tab === item.id}
        aria-selected={tab === item.id}
        aria-controls={`tools-panel-${item.id}`}
        tabindex={tab === item.id ? 0 : -1}
        on:click={() => (tab = item.id)}
        on:keydown={(event) => handleTabKeydown(event, index)}
      >
        <Icon name={item.icon} size={15} strokeWidth={1.9} />{item.label}
      </button>
    {/each}
  </div>

  <div id={`tools-panel-${tab}`} class="settings-panel" role="tabpanel" aria-labelledby={`tools-tab-${tab}`}>
    {#key tab}
      {#if tab === 'password'}
        <GeneratorView {onCopy} onUseInLogin={() => onUseInLogin($generator.password)} />
      {:else if tab === 'passphrase'}
        <PassphraseGeneratorView {onCopy} onUseInLogin={() => onUseInLogin($passphrase.passphrase)} />
      {:else}
        <PasswordStrengthView />
      {/if}
    {/key}
  </div>
</section>

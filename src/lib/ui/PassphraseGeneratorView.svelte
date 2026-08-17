<script lang="ts">
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'

  export let onCopy: (value: string, label: string) => void
  export let onUseInLogin: () => void

  const { passphrase } = useAppStores()

  const separators: { value: string; label: string }[] = [
    { value: '-', label: 'Hyphen' },
    { value: '_', label: 'Underscore' },
    { value: '.', label: 'Period' },
    { value: ' ', label: 'Space' },
  ]
</script>

<section class="passphrase-view">
  <div class="generator-panel">
    <section class="password-output" aria-live="polite">
      <div class="output-heading"><span>Generated passphrase</span>{#if $passphrase.passphrase}<span class:very-strong={$passphrase.strength === 'Very strong'} class="strength-label">{$passphrase.strength}</span>{/if}</div>
      <div class="output-value"><code class:placeholder={!$passphrase.passphrase}>{$passphrase.passphrase || 'Your passphrase will appear here'}</code><div class="output-buttons"><button class="icon-button" aria-label="Generate another passphrase" disabled={!$passphrase.passphrase} on:click={passphrase.generate}><Icon name="refresh" size={15} /></button><button class="icon-button" aria-label="Copy generated passphrase" disabled={!$passphrase.passphrase} on:click={() => $passphrase.passphrase && onCopy($passphrase.passphrase, 'New passphrase')}><Icon name="copy" size={15} /></button></div></div>
      <div class="strength-track" aria-hidden="true"><span class:weak={$passphrase.strength === 'Weak'} class:fair={$passphrase.strength === 'Fair'} style={`width: ${$passphrase.strengthPercent}%`}></span></div>
      <div class="output-meta"><span>{$passphrase.wordCount} words</span><span>About {$passphrase.entropy} bits</span></div>
    </section>

    <section class="generator-settings" aria-label="Passphrase settings">
      <div class="length-setting"><div><strong>Word count</strong><span>More words are harder to guess.</span></div><div class="length-stepper"><button aria-label="Fewer words" disabled={$passphrase.wordCount <= 4} on:click={() => passphrase.changeWordCount(-1)}>&minus;</button><output>{$passphrase.wordCount}</output><button aria-label="More words" disabled={$passphrase.wordCount >= 12} on:click={() => passphrase.changeWordCount(1)}>+</button></div></div>
      <input class="length-range" aria-label="Word count" type="range" min="4" max="12" value={$passphrase.wordCount} on:input={(event) => passphrase.setWordCount(Number(event.currentTarget.value))} />

      <div class="character-setting"><div><strong>Separator</strong><span>The character placed between words.</span></div><div class="generator-toggles">{#each separators as item (item.value)}<button type="button" class:active={$passphrase.separator === item.value} aria-pressed={$passphrase.separator === item.value} on:click={() => passphrase.setSeparator(item.value)}><span class="toggle-check">{#if $passphrase.separator === item.value}<Icon name="check" size={12} />{/if}</span>{item.label}</button>{/each}</div></div>

      <button type="button" class="setting-toggle" class:active={$passphrase.capitalize} aria-pressed={$passphrase.capitalize} on:click={passphrase.toggleCapitalize}><span class="toggle-switch"><span></span></span><span><strong>Capitalize each word</strong><small>Uppercases the first letter of every word.</small></span></button>
      <button type="button" class="setting-toggle" class:active={$passphrase.includeNumber} aria-pressed={$passphrase.includeNumber} on:click={passphrase.toggleIncludeNumber}><span class="toggle-switch"><span></span></span><span><strong>Include a number</strong><small>Appends one digit to a random word.</small></span></button>
    </section>

    <footer class="generator-footer"><button class="primary-button" on:click={passphrase.generate}>{$passphrase.passphrase ? 'Generate again' : 'Generate passphrase'} <Icon name="refresh" size={16} /></button><button class="secondary-button" disabled={!$passphrase.passphrase} on:click={onUseInLogin}>Use in a login</button></footer>
  </div>
</section>

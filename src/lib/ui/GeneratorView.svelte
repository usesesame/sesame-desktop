<script lang="ts">
  import Icon from '../Icon.svelte'
  import { generatorLabels, generatorOptionKeys } from '../generator'
  import { useAppStores } from '../stores/app-stores'

  export let onCopy: (value: string, label: string) => void
  export let onUseInLogin: () => void

  const { generator } = useAppStores()
</script>

<section class="generator-view">
  <div class="generator-panel">
    <section class="password-output" aria-live="polite">
      <div class="output-heading"><span>Generated password</span>{#if $generator.password}<span class:very-strong={$generator.strength === 'Very strong'} class="strength-label">{$generator.strength}</span>{/if}</div>
      <div class="output-value"><code class:placeholder={!$generator.password}>{$generator.password || 'Your password will appear here'}</code><div class="output-buttons"><button class="icon-button" aria-label="Generate another password" disabled={!$generator.password} on:click={generator.generate}><Icon name="refresh" size={15} /></button><button class="icon-button" aria-label="Copy generated password" disabled={!$generator.password} on:click={() => $generator.password && onCopy($generator.password, 'New password')}><Icon name="copy" size={15} /></button></div></div>
      <div class="strength-track" aria-hidden="true"><span class:weak={$generator.strength === 'Weak'} class:fair={$generator.strength === 'Fair'} style={`width: ${$generator.strengthPercent}%`}></span></div>
      <div class="output-meta"><span>{$generator.length} characters</span><span>About {$generator.entropy} bits</span></div>
    </section>

    <section class="generator-settings" aria-label="Password settings">
      <div class="length-setting"><div><strong>Length</strong><span>Longer passwords are harder to guess.</span></div><div class="length-stepper"><button aria-label="Shorten password" disabled={$generator.length <= 12} on:click={() => generator.changeLength(-1)}>&minus;</button><output>{$generator.length}</output><button aria-label="Lengthen password" disabled={$generator.length >= 64} on:click={() => generator.changeLength(1)}>+</button></div></div>
      <input class="length-range" aria-label="Password length" type="range" min="12" max="64" value={$generator.length} on:input={(event) => generator.setLength(Number(event.currentTarget.value))} />

      <div class="character-setting"><div><strong>Characters</strong><span>Every enabled group appears at least once.</span></div><div class="generator-toggles">{#each generatorOptionKeys as option (option)}<button class:active={$generator.options[option]} aria-pressed={$generator.options[option]} on:click={() => generator.toggleOption(option)}><span class="toggle-check">{#if $generator.options[option]}<Icon name="check" size={12} />{/if}</span>{generatorLabels[option]}</button>{/each}</div></div>

      <button class="ambiguity-toggle" class:active={$generator.avoidAmbiguous} aria-pressed={$generator.avoidAmbiguous} on:click={generator.toggleAmbiguous}><span class="toggle-switch"><span></span></span><span><strong>Avoid similar characters</strong><small>Removes I, l, 1, O, 0, and o.</small></span></button>
    </section>

    <footer class="generator-footer"><button class="primary-button" on:click={generator.generate}>{$generator.password ? 'Generate again' : 'Generate password'} <Icon name="refresh" size={16} /></button><button class="secondary-button" disabled={!$generator.password} on:click={onUseInLogin}>Use in a login</button></footer>
  </div>
</section>

<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import { checkPasswordStrength } from '../vault'
  import type { PasswordAnalysis } from '../types'

  // Local state only, sent nowhere but the one check below; gone on unmount or lock.
  let value = ''
  let revealed = false
  let result: PasswordAnalysis | null = null
  let checking = false
  let debounceTimer: ReturnType<typeof window.setTimeout> | undefined
  let requestToken = 0

  function scheduleCheck() {
    if (debounceTimer) window.clearTimeout(debounceTimer)
    if (!value) {
      result = null
      checking = false
      return
    }
    checking = true
    debounceTimer = window.setTimeout(() => void runCheck(), 220)
  }

  async function runCheck() {
    const token = (requestToken += 1)
    const password = value
    try {
      const analysis = await checkPasswordStrength(password)
      if (token === requestToken) result = analysis
    } catch {
      if (token === requestToken) result = null
    } finally {
      if (token === requestToken) checking = false
    }
  }

  function clear() {
    value = ''
    result = null
    checking = false
    requestToken += 1
    if (debounceTimer) window.clearTimeout(debounceTimer)
  }

  onDestroy(() => {
    if (debounceTimer) window.clearTimeout(debounceTimer)
    value = ''
  })

  $: label = !result ? '' : result.score >= 4 ? 'Very strong' : result.score >= 3 ? 'Strong' : 'Weak'
  $: percent = !result ? 0 : Math.min(100, Math.max(8, result.score * 25))
</script>

<section class="strength-checker-view">
  <div class="generator-panel">
    <section class="password-output">
      <div class="output-heading"><span>Password to check</span>{#if label}<span class:very-strong={label === 'Very strong'} class="strength-label">{label}</span>{/if}</div>
      <div class="strength-input-row">
        <input
          class="strength-input"
          name="password-to-check"
          type={revealed ? 'text' : 'password'}
          autocomplete="off"
          spellcheck="false"
          placeholder="Paste or type a password…"
          aria-label="Password to check"
          bind:value
          on:input={scheduleCheck}
        />
        <button type="button" class="icon-button" aria-label={revealed ? 'Hide password' : 'Show password'} on:click={() => (revealed = !revealed)}><Icon name={revealed ? 'eye-off' : 'eye'} size={15} /></button>
        <button type="button" class="icon-button" aria-label="Clear" disabled={!value} on:click={clear}><Icon name="trash" size={15} /></button>
      </div>
      <div class="strength-track" aria-hidden="true"><span class:weak={label === 'Weak'} style={`width: ${percent}%`}></span></div>
      <p class="strength-privacy-note">Checked on this device. Nothing typed here is saved or sent.</p>
    </section>

    <section class="generator-settings" aria-label="Strength result" aria-live="polite">
      {#if checking}
        <p class="strength-status">Checking…</p>
      {:else if result && result.issues.length > 0}
        <ul class="strength-issues">
          {#each result.issues as issue (issue.kind)}
            <li><Icon name="alert" size={14} />{issue.explanation}</li>
          {/each}
        </ul>
      {:else if result}
        <p class="strength-status good"><Icon name="check" size={14} />No issues found in this password.</p>
      {:else}
        <p class="strength-status">Type or paste a password above to check it.</p>
      {/if}
    </section>
  </div>
</section>

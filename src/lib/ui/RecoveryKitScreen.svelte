<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { SvelteSet } from 'svelte/reactivity'
  import SetupProgress from './SetupProgress.svelte'

  export let recoveryKit = ''
  export let recoveryConfirmed = false
  export let onContinue: () => void
  export let verifyMode = false
  export let onViewKit: (() => void) | undefined = undefined
  export let onSaveToFile: ((kit: string) => Promise<string | null>) | undefined = undefined

  let savingToFile = false
  let saveError = ''
  let savedFileName = ''

  async function handleSaveToFile() {
    if (!onSaveToFile || savingToFile) return
    savingToFile = true
    saveError = ''
    try {
      const name = await onSaveToFile(recoveryKit)
      if (name) savedFileName = name
    } catch {
      saveError = 'Sesame could not save the recovery kit to a file. Try again, or write it down instead.'
    } finally {
      savingToFile = false
    }
  }

  // The kit was shown once already, so a wrong group is a transcription slip, not a guessing attack.
  const maxAttempts = 5

  let heading: HTMLHeadingElement
  let savedConfirmed = false
  let verifyInputs: string[] = []
  let verifyGroups: number[] = []
  let verifyError = ''
  let attempts = 0
  let readyToSubmit = false

  const groups = parseKit(recoveryKit)

  onMount(() => {
    heading?.focus({ preventScroll: true })
    if (verifyMode) {
      verifyGroups = chooseGroups(groups.length, 2)
      verifyInputs = verifyGroups.map(() => '')
    }
  })

  onDestroy(() => {
    savedConfirmed = false
    verifyInputs = []
    verifyGroups = []
    verifyError = ''
  })

  function parseKit(kit: string): string[] {
    return kit.split('-').filter((g) => g.length > 0)
  }

  function chooseGroups(total: number, count: number): number[] {
    if (total <= count) return Array.from({ length: total }, (_, i) => i)
    const chosen = new SvelteSet<number>()
    while (chosen.size < count) {
      chosen.add(Math.floor(Math.random() * total))
    }
    return Array.from(chosen).sort((a, b) => a - b)
  }

  function normalize(value: string): string {
    return value.trim().toUpperCase().replace(/\s+/g, '')
  }

  $: readyToSubmit = !verifyMode
    ? savedConfirmed
    : verifyGroups.length === 2 && verifyInputs.every((value) => normalize(value).length === 5)

  function handleContinue() {
    if (!verifyMode) {
      recoveryConfirmed = savedConfirmed
      if (savedConfirmed) onContinue()
      return
    }
    attempts += 1
    const matches = verifyGroups.length === 2
      && verifyGroups.every((groupIndex, i) => normalize(verifyInputs[i]) === groups[groupIndex])
    if (matches) {
      recoveryConfirmed = true
      verifyError = ''
      onContinue()
    } else if (attempts >= maxAttempts && onViewKit) {
      verifyError = 'These groups still do not match. Look at your written kit again before trying once more.'
    } else {
      verifyError = 'One or more groups do not match. Check your written kit and try again.'
    }
  }

  function startOver() {
    savedConfirmed = false
    verifyInputs = verifyGroups.map(() => '')
    verifyError = ''
  }
</script>

<main class="recovery-shell">
  <section class="recovery-card" aria-labelledby="recovery-kit-heading" aria-describedby="recovery-kit-description">
    <div class="brand"><img class="sesame-mark" src="/favicon.svg" alt="" /><span>Sesame</span><span class="brand-progress"><SetupProgress step={2} /></span></div>
    <p class="eyebrow">Recovery kit</p>
    <h1 bind:this={heading} id="recovery-kit-heading" tabindex="-1">
      {verifyMode ? 'Verify your kit' : 'Write this down.'}
    </h1>
    <p id="recovery-kit-description" class="lede">
      {#if verifyMode}
        Enter the groups Sesame asks for to prove you saved the kit. The kit is not shown again.
      {:else}
        You need this kit if you move to a different computer or Windows cannot open this vault. Sesame will not show it again.
      {/if}
    </p>

    {#if !verifyMode}
      <code class="recovery-code">{#each groups as group, index (index)}<span>{group}{index < groups.length - 1 ? '-' : ''}</span>{/each}</code>
      {#if onSaveToFile}
        <button type="button" class="text-button save-file-button" on:click={handleSaveToFile} disabled={savingToFile}>
          {savingToFile ? 'Saving…' : 'Save to a file'}
        </button>
        {#if savedFileName}
          <p class="save-status" role="status">Saved as {savedFileName}. Move it somewhere Sesame cannot reach.</p>
        {/if}
        {#if saveError}
          <p class="verify-error" role="alert">{saveError}</p>
        {/if}
      {/if}
      <label class="recovery-confirm"><input type="checkbox" bind:checked={savedConfirmed} /> <span>I saved this outside Sesame.</span></label>
    {:else}
      <div class="verify-groups" role="group" aria-label="Recovery kit verification">
        {#each verifyGroups as groupIndex, i (groupIndex)}
          <label class="verify-group">
            <span>Group {groupIndex + 1}</span>
            <input
              type="text"
              maxlength="6"
              autocomplete="off"
              autocapitalize="characters"
              aria-invalid={verifyError ? 'true' : undefined}
              bind:value={verifyInputs[i]}
            />
          </label>
        {/each}
      </div>
      {#if verifyError}
        <p class="verify-error" role="alert">{verifyError}</p>
      {/if}
      <button type="button" class="text-button" on:click={startOver}>Start over</button>
      {#if attempts >= maxAttempts && onViewKit}
        <button type="button" class="text-button" on:click={onViewKit}>View my kit again</button>
      {/if}
    {/if}

    <button type="button" class="primary-button full" disabled={!readyToSubmit} on:click={handleContinue}>
      {verifyMode ? 'Verify' : 'Continue'}
    </button>
    <p class="tiny-note">Do not save the kit in this vault.</p>
  </section>
</main>

<style>
  .recovery-shell {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    padding: 24px;
    background: var(--bg);
  }
  .recovery-card {
    width: min(100%, 420px);
    padding: 28px;
    border-radius: var(--radius-lg);
    background: var(--surface);
    border: 0;
    box-shadow: var(--shadow-raise);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 18px;
    font-weight: 700;
  }
  .sesame-mark { width: 28px; height: 28px; }
  .brand-progress { margin-left: auto; }
  .eyebrow {
    margin: 0 0 6px;
    font-size: var(--type-1);
    font-weight: 700;
    color: var(--eyebrow);
  }
  h1 {
    margin: 0 0 10px;
    font-size: 22px;
    font-family: var(--font-display);
  }
  .lede {
    margin: 0 0 18px;
    color: var(--text-muted);
  }
  /* Each group is its own box, so a line can only ever break between groups. */
  .recovery-code {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: var(--space-2) 0;
    width: 100%;
    padding: var(--space-4);
    margin-bottom: var(--space-4);
    border-radius: var(--radius-md);
    background: var(--surface-inset);
    border: 1px solid var(--border-soft);
    user-select: all;
  }
  .recovery-code span {
    color: var(--accent-link);
    font-size: var(--type-4);
    font-weight: 700;
    letter-spacing: .1em;
  }
  .recovery-confirm {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 18px;
    font-size: 13px;
    cursor: pointer;
  }
  .verify-groups {
    display: grid;
    gap: 12px;
    margin-bottom: 14px;
  }
  .verify-group {
    display: grid;
    gap: 4px;
    font-size: 13px;
  }
  .verify-group input {
    padding: 10px;
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    background: var(--bg);
    color: var(--text);
    font: 16px/1.3 ui-monospace, monospace;
    text-transform: uppercase;
  }
  .verify-error {
    margin: 0 0 12px;
    padding: 10px;
    border-radius: var(--radius-sm);
    background: var(--danger-tint);
    color: var(--danger);
    font-size: 13px;
  }
  .text-button {
    justify-self: start;
    margin-bottom: var(--space-3);
    border: 0;
    border-radius: var(--radius-sm);
    padding: var(--space-2) var(--space-3);
    background: var(--surface-inset);
    color: var(--accent-link);
    font-size: var(--type-2);
    font-weight: 600;
    cursor: pointer;
  }
  .text-button:hover:not(:disabled) { background: var(--tint); }
  .text-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .save-file-button {
    display: block;
    margin-bottom: 10px;
  }
  .save-status {
    margin: -4px 0 14px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .primary-button {
    padding: 12px 18px;
    border: none;
    border-radius: 10px;
    background: var(--accent);
    color: var(--on-accent);
    font-weight: 600;
    cursor: pointer;
  }
  .primary-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .full { width: 100%; }
  .tiny-note {
    margin: 12px 0 0;
    font-size: 12px;
    color: var(--text-muted);
  }
</style>

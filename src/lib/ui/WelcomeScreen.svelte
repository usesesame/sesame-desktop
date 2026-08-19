<script lang="ts">
  import { onMount } from 'svelte'
  import Icon from '../Icon.svelte'

  export let onStart: () => void

  let heading: HTMLHeadingElement

  onMount(() => heading?.focus({ preventScroll: true }))
</script>

<main class="welcome-intro">
  <section class="welcome-card" aria-labelledby="welcome-heading" aria-describedby="welcome-description">
    <div class="brand"><img class="sesame-mark" src="/favicon.svg" alt="" /><span>Sesame</span></div>
    <h1 bind:this={heading} id="welcome-heading" tabindex="-1">Welcome to Sesame</h1>
    <p id="welcome-description" class="lede">
      Sesame keeps your passwords in an encrypted vault on this computer. Setup has four short steps, and you can change any of it later in Settings.
    </p>

    <ul class="welcome-steps">
      <li><span class="step-icon"><Icon name="vault" size={17} /></span><span>Create your vault with a master password.</span></li>
      <li><span class="step-icon"><Icon name="file-key" size={17} /></span><span>Write down a recovery kit that opens the vault if you forget that password.</span></li>
      <li><span class="step-icon"><Icon name="key" size={17} /></span><span>Pick a PIN or Windows Hello for everyday unlock.</span></li>
    </ul>

    <button type="button" class="start-button" on:click={onStart}>Start setup</button>
    <p class="tiny-note">Your vault, master password, and recovery kit stay on this computer.</p>
  </section>
</main>

<style>
  .welcome-intro {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    padding: var(--space-5);
    background: var(--bg);
  }
  .welcome-card {
    width: min(100%, 460px);
    padding: var(--space-6);
    border: 0;
    border-radius: var(--radius-lg);
    background: var(--surface);
    box-shadow: var(--shadow-raise);
  }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: var(--space-5); font-weight: 700; }
  .sesame-mark { width: 28px; height: 28px; }
  h1 {
    margin: 0 0 10px;
    color: var(--text-heading);
    font-family: var(--font-display);
    font-size: var(--type-5);
    line-height: 1.2;
  }
  h1:focus-visible { outline: none; }
  .lede { margin: 0; color: var(--text-muted); font-size: var(--type-3); line-height: 1.55; }
  .welcome-steps { display: grid; gap: var(--space-3); margin: var(--space-5) 0; padding: 0; list-style: none; }
  .welcome-steps li {
    display: grid;
    grid-template-columns: 30px minmax(0, 1fr);
    align-items: start;
    gap: var(--space-3);
    color: var(--text);
    font-size: var(--type-2);
    line-height: 1.5;
  }
  .step-icon {
    display: grid;
    width: 30px;
    height: 30px;
    place-items: center;
    border-radius: var(--radius-sm);
    color: var(--chip-icon);
    background: var(--chip-bg);
  }
  .start-button {
    width: 100%;
    border: 0;
    border-radius: var(--radius-md);
    padding: 13px 18px;
    color: var(--on-accent);
    background: var(--accent);
    font-size: var(--type-2);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--t-fast) ease;
  }
  .start-button:hover { background: var(--accent-hover); }
  .start-button:active { background: var(--accent-active); }
  .tiny-note { margin: var(--space-4) 0 0; color: var(--text-faint); font-size: var(--type-1); line-height: 1.55; }
</style>

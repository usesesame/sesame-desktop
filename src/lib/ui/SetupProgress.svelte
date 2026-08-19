<script lang="ts">
  export let step: number
  export let total = 4

  $: dots = Array.from({ length: total }, (_, index) => index + 1)
</script>

<p class="setup-progress">
  <span class="setup-progress-dots" aria-hidden="true">
    {#each dots as dot (dot)}
      <span class="dot" class:done={dot < step} class:current={dot === step}></span>
    {/each}
  </span>
  <span>Step {step} of {total}</span>
</p>

<style>
  .setup-progress {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin: 0;
    color: var(--text-muted);
    font-size: var(--type-1);
    font-weight: 600;
  }
  .setup-progress-dots { display: flex; gap: 5px; }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: var(--radius-pill);
    background: var(--border-strong);
    transition: width var(--t-fast) ease, background var(--t-fast) ease;
  }
  .dot.done { background: var(--accent-link); }
  .dot.current { width: 18px; background: var(--accent); }
</style>

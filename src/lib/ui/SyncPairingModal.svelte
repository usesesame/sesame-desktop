<script lang="ts">
  import ModalShell from './ModalShell.svelte'

  export let open = false
  export let code = ''
  export let phase: 'idle' | 'starting' | 'waiting' | 'done' = 'idle'
  export let secondsLeft = 0
  export let doneLabel = ''
  export let error = ''
  export let olderKeyRefused = false
  export let allowOlderKeys = false
  export let onClose: () => void
  export let onRetry: () => void

  $: minutes = Math.floor(secondsLeft / 60)
  $: seconds = String(secondsLeft % 60).padStart(2, '0')
  $: grouped = code.length === 10 ? `${code.slice(0, 5)} ${code.slice(5)}` : code
</script>

{#if open}
  <ModalShell {open} {onClose} labelledby="sync-pairing-title" describedby="sync-pairing-body" ariaBusy={phase === 'waiting' || phase === 'starting'}>
    <h2 id="sync-pairing-title">Add a device</h2>
    <div id="sync-pairing-body">
      {#if phase === 'done'}
        <p class="modal-lede" role="status">{doneLabel} was added to this vault.</p>
      {:else if phase === 'waiting'}
        <p class="modal-lede">
          On the new device, open Sesame Sync, choose Join with a code, and type this code. Keep
          this window open until it finishes.
        </p>
        <p class="pairing-code" aria-label="Pairing code">{grouped}</p>
        <p class="pairing-note" role="status">
          The code works once and expires in {minutes}:{seconds}. It is never sent to the server.
        </p>
      {:else if phase === 'starting'}
        <p class="modal-lede" role="status">Getting a code…</p>
      {:else}
        <p class="modal-lede">Sesame could not start pairing.</p>
      {/if}
      {#if error}<p class="form-error" role="alert">{error}</p>{/if}
      {#if olderKeyRefused && phase === 'idle'}
        <label class="pairing-allow"><input name="allow-older-key-exchange" type="checkbox" bind:checked={allowOlderKeys} /><span>Allow a device that only supports the older key exchange.</span></label>
      {/if}
    </div>
    <div class="modal-actions">
      {#if phase === 'done'}
        <button type="button" class="primary-button" on:click={onClose}>Done</button>
      {:else}
        <button type="button" class="secondary-button" on:click={onClose}>Cancel</button>
        {#if phase === 'idle'}
          <button type="button" class="primary-button" on:click={onRetry}>Show a new code</button>
        {/if}
      {/if}
    </div>
  </ModalShell>
{/if}

<style>
  .pairing-code {
    margin: var(--space-4) 0;
    color: var(--text-heading);
    font-family: var(--font-code);
    font-size: var(--type-5, 1.6rem);
    letter-spacing: 0.14em;
  }
  .pairing-allow {
    display: flex;
    gap: var(--space-2);
    align-items: flex-start;
    margin-top: var(--space-3);
    color: var(--text);
    font-size: var(--type-2);
    line-height: 1.5;
  }
  .pairing-note {
    margin: 0;
    color: var(--text-muted);
    font-size: var(--type-2);
    line-height: 1.5;
  }
</style>

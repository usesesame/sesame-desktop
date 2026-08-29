<script lang="ts">
  import ModalShell from './ModalShell.svelte'

  export let open = false
  export let working = false
  export let error = ''
  export let onCancel: () => void
  export let onEnable: () => void

  let understood = false

  $: if (!open) understood = false
</script>

{#if open}
  <ModalShell {open} onClose={onCancel} labelledby="sync-enable-title" describedby="sync-enable-body" ariaBusy={working}>
    <h2 id="sync-enable-title">Turn on Sync</h2>
    <div id="sync-enable-body">
      <p class="modal-lede">
        Sync copies an encrypted vault between your own devices. Sesame stores the encrypted
        file and cannot read it.
      </p>

      <p class="sync-unsafe" role="alert">
        This is an unreviewed preview. Every issue found in the reviews on 2026-07-30 and
        2026-08-01 has been fixed, but the protocol changed while fixing them and nobody
        outside the project has reviewed it since. Use a throwaway vault, not one you rely on.
      </p>

      <ul class="sync-facts">
        <li><strong>Sesame cannot recover a synced vault.</strong> If you lose every device, your recovery kit is the only way back.</li>
        <li><strong>Each new device needs approval</strong> from a device that is already syncing and unlocked.</li>
        <li><strong>Your master password and recovery kit are never sent.</strong> Neither is a PIN, a TOTP seed, or a backup code.</li>
        <li><strong>Removing another device</strong> changes your vault key, so it asks for your master password and gives you a new recovery kit.</li>
        <li><strong>Turning Sync off here</strong> removes this device's keys and leaves the local vault untouched.</li>
      </ul>

      <label class="sync-confirm">
        <input name="sync-enable-understood" type="checkbox" bind:checked={understood} disabled={working} />
        <span>I have my recovery kit saved outside Sesame.</span>
      </label>

      {#if error}<p class="form-error" role="alert">{error}</p>{/if}
    </div>

    <div class="modal-actions">
      <button type="button" class="secondary-button" on:click={onCancel} disabled={working}>Cancel</button>
      <button type="button" class="primary-button" on:click={onEnable} disabled={!understood || working}>
        {working ? 'Turning on Sync…' : 'Turn on Sync'}
      </button>
    </div>
  </ModalShell>
{/if}

<style>
  .sync-unsafe {
    color: var(--danger);
    font-weight: 600;
  }

  .sync-facts {
    display: grid;
    gap: var(--space-3);
    margin: var(--space-4) 0;
    padding: 0;
    list-style: none;
  }
  .sync-facts li {
    position: relative;
    padding-left: var(--space-5);
    color: var(--text-2);
    font-size: var(--type-2);
    line-height: 1.5;
  }
  .sync-facts li::before {
    content: "";
    position: absolute;
    top: .5em;
    left: var(--space-2);
    width: 6px;
    height: 6px;
    border-radius: var(--radius-pill);
    background: var(--gold);
  }
  .sync-facts strong { color: var(--text-heading); }
  .sync-confirm {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    margin-top: var(--space-4);
    color: var(--text);
    font-size: var(--type-2);
    cursor: pointer;
  }
</style>

<script lang="ts">
  import ModalShell from './ModalShell.svelte'

  export let open = false
  export let working = false
  export let error = ''
  export let onCancel: () => void
  export let onEnable: (label: string) => void

  let understood = false
  let label = 'This computer'

  $: if (!open) understood = false
</script>

{#if open}
  <ModalShell {open} onClose={onCancel} labelledby="sync-enable-title" describedby="sync-enable-body" ariaBusy={working}>
    <h2 id="sync-enable-title">Turn on Sync</h2>
    <div id="sync-enable-body">
      <p class="modal-lede">
        Sync keeps an encrypted copy of your vault on a server so you can use it on your other
        devices, and the server has no key to read it.
      </p>

      <p class="sync-notice" role="note">
        Sync has not had an independent security review. Keep backups while you try it.
      </p>

      <ul class="sync-facts">
        <li>Keep a vault backup and your recovery kit. You need an approved device to add another one, so Sync cannot replace a backup if you lose every device.</li>
        <li>To add a device, enter a code from an unlocked device that already syncs this vault.</li>
        <li>Removing a device changes the vault key, so Sesame asks for your master password and gives you a new recovery kit.</li>
        <li>Turning Sync off here removes this device from the synced vault and keeps its local vault.</li>
      </ul>

      <label class="sync-field">
        <span>Name this device</span>
        <input name="sync-device-name" type="text" bind:value={label} maxlength="40" disabled={working} autocomplete="off" />
      </label>

      <label class="sync-confirm">
        <input name="sync-enable-understood" type="checkbox" bind:checked={understood} disabled={working} />
        <span>I have my recovery kit saved outside Sesame.</span>
      </label>

      {#if error}<p class="form-error" role="alert">{error}</p>{/if}
    </div>

    <div class="modal-actions">
      <button type="button" class="secondary-button" on:click={onCancel} disabled={working}>Cancel</button>
      <button type="button" class="primary-button" on:click={() => onEnable(label.trim())} disabled={!understood || !label.trim() || working}>
        {working ? 'Turning on Sync…' : 'Turn on Sync'}
      </button>
    </div>
  </ModalShell>
{/if}

<style>
  .sync-notice {
    color: var(--text-2);
    font-size: var(--type-3);
    line-height: 1.5;
  }

  .sync-facts {
    display: grid;
    gap: var(--space-3);
    margin: var(--space-4) 0;
    padding: 0 0 0 var(--space-4);
  }
  .sync-facts li {
    color: var(--text-2);
    font-size: var(--type-3);
    line-height: 1.5;
  }
  .sync-field {
    display: grid;
    gap: var(--space-2);
    margin-top: var(--space-4);
    color: var(--text);
    font-size: var(--type-2);
  }
  .sync-field input,
  .sync-field input:not([type="checkbox"]) {
    width: min(100%, 20rem);
    padding: 10px var(--space-3);
    border: 1px solid var(--field-border);
    border-radius: var(--radius-md);
    color: var(--text);
    background: var(--field-bg);
    font-size: var(--type-3);
  }
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

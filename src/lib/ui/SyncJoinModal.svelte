<script lang="ts">
  import ModalShell from './ModalShell.svelte'

  export let open = false
  export let working = false
  export let resuming = false
  export let error = ''
  export let onCancel: () => void
  export let onJoin: (code: string, label: string, masterPassword: string) => void

  let code = ''
  let label = 'This computer'
  let password = ''

  $: if (!open) {
    code = ''
    password = ''
  }
  $: ready = (resuming || code.replace(/[\s-]/g, '').length === 10) && label.trim().length > 0 && password.length > 0
</script>

{#if open}
  <ModalShell {open} onClose={onCancel} labelledby="sync-join-title" describedby="sync-join-body" ariaBusy={working}>
    <h2 id="sync-join-title">{resuming ? 'Finish joining' : 'Join with a code'}</h2>
    <div id="sync-join-body">
      {#if resuming}
      <p class="modal-lede">
        Finish joining with your master password. Sesame replaces this device's vault with the
        synced vault, saves a recovery copy and gives you a new recovery kit.
      </p>
      {:else}
      <p class="modal-lede">
        On a device that already syncs this vault, choose Add a device and type the code it shows
        here. Joining replaces what is in Sesame on this device with the synced vault. A copy of
        the current vault is saved first as a recovery copy, and you get a new recovery kit.
      </p>
      <label class="sync-field">
        <span>Code from the other device</span>
        <input name="sync-code" type="text" bind:value={code} maxlength="12" autocomplete="off" autocapitalize="characters" spellcheck="false" disabled={working} />
      </label>
      <label class="sync-field">
        <span>Name this device</span>
        <input name="sync-device-name" type="text" bind:value={label} maxlength="40" autocomplete="off" disabled={working} />
      </label>
      {/if}
      <label class="sync-field">
        <span>Master password</span>
        <input name="sync-master-password" type="password" bind:value={password} autocomplete="current-password" disabled={working} />
      </label>
      {#if working}<p class="sync-wait" role="status">{resuming ? 'Finishing the join. Keep this window open.' : 'Waiting for the other device. Keep both windows open.'}</p>{/if}
      {#if error}<p class="form-error" role="alert">{error}</p>{/if}
    </div>
    <div class="modal-actions">
      <button type="button" class="secondary-button" on:click={onCancel}>Cancel</button>
      <button type="button" class="primary-button" disabled={!ready || working} on:click={() => onJoin(code, label.trim(), password)}>
        {working ? 'Joining…' : resuming ? 'Finish joining' : 'Join vault'}
      </button>
    </div>
  </ModalShell>
{/if}

<style>
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
  .sync-wait {
    margin: var(--space-4) 0 0;
    color: var(--text-muted);
    font-size: var(--type-2);
  }
</style>

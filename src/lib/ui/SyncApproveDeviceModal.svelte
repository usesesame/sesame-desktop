<script lang="ts">
  import ModalShell from './ModalShell.svelte'

  export let open = false
  export let deviceLabel = ''
  /** Grouped hex of the joining device's signing key. Compared by eye, on both screens. */
  export let fingerprint = ''
  export let requestedAt = ''
  export let working = false
  export let error = ''
  export let onDeny: () => void
  export let onApprove: () => void

  let matched = false

  $: if (!open) matched = false

  function formatWhen(value: string): string {
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  }
</script>

{#if open}
  <ModalShell {open} onClose={onDeny} labelledby="sync-approve-title" describedby="sync-approve-body" ariaBusy={working}>
    <h2 id="sync-approve-title">Approve this device?</h2>
    <div id="sync-approve-body">
      <p class="modal-lede">
        A device asked to join your vault. Approving it sends that device a copy of your vault
        key, encrypted so only it can open it.
      </p>

      <div class="sync-device-card">
        <p class="sync-device-name">{deviceLabel || 'Unnamed device'}</p>
        {#if requestedAt}<p class="sync-device-meta">Asked {formatWhen(requestedAt)}</p>{/if}
        <!-- The fingerprint is the only thing standing between the user and approving a device that is not theirs. -->
        <p class="sync-device-label">Fingerprint</p>
        <code class="sync-fingerprint">{fingerprint}</code>
      </div>

      <p class="sync-warning">
        Check this fingerprint matches the one shown on the joining device. If it does not
        match, deny it and remove the device.
      </p>

      <label class="sync-confirm">
        <input name="sync-fingerprint-matched" type="checkbox" bind:checked={matched} disabled={working} />
        <span>The fingerprint matches the other device.</span>
      </label>

      {#if error}<p class="form-error" role="alert">{error}</p>{/if}
    </div>

    <div class="modal-actions">
      <button type="button" class="secondary-button" on:click={onDeny} disabled={working}>Deny</button>
      <button type="button" class="primary-button" on:click={onApprove} disabled={!matched || working}>
        {working ? 'Approving…' : 'Approve device'}
      </button>
    </div>
  </ModalShell>
{/if}

<style>
  .sync-device-card {
    margin: var(--space-4) 0;
    border-radius: var(--radius-md);
    padding: var(--space-4);
    background: var(--surface-inset);
  }
  .sync-device-name {
    margin: 0;
    color: var(--text-heading);
    font-size: var(--type-3);
    font-weight: 650;
  }
  .sync-device-meta {
    margin: var(--space-1) 0 0;
    color: var(--text-muted);
    font-size: var(--type-1);
  }
  .sync-device-label {
    margin: var(--space-4) 0 var(--space-2);
    color: var(--text-muted);
    font-size: var(--type-1);
  }
  .sync-fingerprint {
    display: block;
    color: var(--text-heading);
    font-family: var(--font-code);
    font-size: var(--type-2);
    letter-spacing: .06em;
    line-height: 1.6;
    overflow-wrap: anywhere;
    user-select: all;
  }
  .sync-warning {
    margin: 0;
    color: var(--warn-text);
    font-size: var(--type-2);
    line-height: 1.5;
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

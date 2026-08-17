<script lang="ts">
  // Sync has not passed its review.
  import { onMount } from 'svelte'
  import Icon from '../Icon.svelte'
  import SyncEnableModal from './SyncEnableModal.svelte'
  import SyncApproveDeviceModal from './SyncApproveDeviceModal.svelte'
  import SyncConflictModal from './SyncConflictModal.svelte'
  import { createSyncPreviewController } from '../controllers/sync-preview-controller'

  const syncPreview = createSyncPreviewController()

  onMount(() => {
    void syncPreview.refresh()
  })

  const stateLabels: Record<string, string> = {
    not_enrolled: 'Not set up on this device',
    pending: 'Waiting for another device to approve',
    approved: 'Active',
    revoked: 'Revoked',
  }

  $: summary = stateLabels[$syncPreview.state] ?? 'Unknown'
  $: others = $syncPreview.devices.filter((device) => !device.isThisDevice)

  let removing = ''
  let removalPassword = ''
  let joining = false
  let joinPassword = ''
  let showBackups = false

  $: coordinatorNote = describeCoordinator($syncPreview.coordinator)

  function describeCoordinator(state: {
    phase: string
    halt: string
    consecutiveFailures: number
    lastSuccessRevision: number
  }): string {
    if (state.phase === 'halted') {
      switch (state.halt) {
        case 'revoked':
          return 'This device was removed from the vault. Set Sesame Sync up again to rejoin.'
        case 'not_entitled':
          return 'Your subscription does not cover Sesame Sync. You can still download and remove devices.'
        case 'incompatible':
          return 'Sesame Sync needs a newer version of this app.'
        case 'conflict':
          return 'Two devices changed this vault. Choose which version to keep.'
        case 'locked':
          return 'Unlock Sesame to keep syncing.'
        default:
          return 'Sesame Sync stopped.'
      }
    }
    if (state.phase === 'retrying') {
      return `Could not reach Sesame Sync. Trying again (${state.consecutiveFailures}).`
    }
    if (state.phase === 'working') return 'Syncing…'
    if (state.lastSuccessRevision > 0) return `Up to date at version ${state.lastSuccessRevision}.`
    return ''
  }

  async function confirmRemoval() {
    await syncPreview.removeDevice(removing, removalPassword)
    removalPassword = ''
    removing = ''
  }

  async function confirmJoin() {
    await syncPreview.adoptVault(joinPassword)
    joinPassword = ''
    joining = false
  }
</script>

<article>
  <span class="settings-icon"><Icon name="refresh" size={16} /></span>
  <div class="setting-copy">
    <strong>Sesame Sync</strong>
    <p>{summary}. Sesame cannot read what it stores.</p>
    {#if $syncPreview.loadError}
      <p class="sync-note">{$syncPreview.loadError}</p>
    {/if}
    {#if coordinatorNote}
      <p class="sync-note">{coordinatorNote}</p>
    {/if}
    {#if $syncPreview.lastTransfer}
      <p class="sync-done">{$syncPreview.lastTransfer}</p>
    {/if}
  </div>
  {#if $syncPreview.enrolled}
    <div class="sync-actions">
      {#if $syncPreview.state === 'approved'}
        <button
          type="button"
          class="secondary-button settings-manage"
          disabled={$syncPreview.working}
          on:click={syncPreview.syncNow}
        >
          {$syncPreview.working ? 'Syncing…' : 'Sync now'}
        </button>
      {:else if $syncPreview.state === 'pending'}
        <button
          type="button"
          class="secondary-button settings-manage"
          disabled={$syncPreview.working}
          on:click={() => (joining = true)}
        >
          Join this vault
        </button>
      {/if}
      <button
        type="button"
        class="text-button"
        disabled={$syncPreview.working}
        on:click={() => {
          showBackups = !showBackups
          if (showBackups) void syncPreview.loadBackups()
        }}
      >
        {showBackups ? 'Hide recovery copies' : 'Recovery copies'}
      </button>
      <button
        type="button"
        class="text-button"
        disabled={$syncPreview.working}
        on:click={syncPreview.refresh}
      >
        Refresh
      </button>
    </div>
  {:else}
    <button
      type="button"
      class="secondary-button settings-manage"
      disabled={$syncPreview.working}
      on:click={syncPreview.openEnable}
    >
      Set up
    </button>
  {/if}
</article>

<article class="sync-caution">
  <span class="settings-icon"><Icon name="shield-alert" size={16} /></span>
  <div class="setting-copy">
    <strong>Unreviewed preview</strong>
    <p>The protocol changed after the last review. Use a throwaway vault.</p>
  </div>
</article>

{#if $syncPreview.state === 'pending' && $syncPreview.ownFingerprint}
<div class="sync-own-code">
    <strong>This device's code</strong>
    <p>
      Read this out on the device you are approving from. Both screens must
      show the same code before you approve.
    </p>
    <code>{$syncPreview.ownFingerprint}</code>
  </div>
{/if}
{#if $syncPreview.removalRecoveryKit}
  <div class="sync-own-code">
    <strong>Write down your new recovery kit</strong>
    <p>
      Your vault key changed, so every earlier recovery kit stopped working.
      This is shown once.
    </p>
    <code>{$syncPreview.removalRecoveryKit}</code>
    <button type="button" class="text-button" on:click={syncPreview.dismissRecoveryKit}>
      I have written it down
    </button>
  </div>
{/if}
{#if showBackups}
  <div class="sync-own-code">
    <strong>Recovery copies</strong>
    <p>
      Saved on this device before a version was replaced. Restoring one
      replaces what is in Sesame now, and saves a copy of that first.
    </p>
    {#if $syncPreview.backups.length === 0}
      <p>No recovery copies on this device.</p>
    {:else}
      <ul class="sync-devices">
        {#each $syncPreview.backups as backup (backup.name)}
          <li>
            <span class="sync-device-label">
              {backup.side === 'this-device' ? 'This device' : 'Other device'}, version
              {backup.revision}
            </span>
            <span class="sync-device-state">{backup.entryCount} logins</span>
            <button
              type="button"
              class="text-button"
              disabled={$syncPreview.working}
              on:click={() => syncPreview.restoreBackup(backup.name)}
            >
              Restore
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
{/if}
{#if removing}
  <div class="sync-own-code">
    <strong>Remove this device</strong>
    <p>
      Sesame will change your vault key and give the new one to the devices
      that are staying, so the removed device cannot read future changes.
      Enter your master password to confirm.
    </p>
    <input
      type="password"
      bind:value={removalPassword}
      placeholder="Master password"
      autocomplete="current-password"
    />
    <div class="modal-actions">
      <button
        type="button"
        class="secondary-button"
        disabled={$syncPreview.working}
        on:click={() => {
          removing = ''
          removalPassword = ''
        }}
      >
        Cancel
      </button>
      <button
        type="button"
        class="primary-button"
        disabled={!removalPassword || $syncPreview.working}
        on:click={confirmRemoval}
      >
        Remove device
      </button>
    </div>
  </div>
{/if}
{#if joining}
  <div class="sync-own-code">
    <strong>Join this vault</strong>
    <p>
      Another device approved this one. Joining replaces what is in Sesame on
      this device with the synced vault, and gives you a new recovery kit.
      Enter your master password to confirm.
    </p>
    <input
      type="password"
      bind:value={joinPassword}
      placeholder="Master password"
      autocomplete="current-password"
    />
    <div class="modal-actions">
      <button
        type="button"
        class="secondary-button"
        disabled={$syncPreview.working}
        on:click={() => {
          joining = false
          joinPassword = ''
        }}
      >
        Cancel
      </button>
      <button
        type="button"
        class="primary-button"
        disabled={!joinPassword || $syncPreview.working}
        on:click={confirmJoin}
      >
        Join vault
      </button>
    </div>
  </div>
{/if}
{#if others.length > 0}
  <ul class="sync-devices">
    {#each others as device (device.deviceId)}
      <li>
        <span class="sync-device-label">{device.label || 'Unnamed device'}</span>
        <span class="sync-device-state">{stateLabels[device.state] ?? device.state}</span>
        <button
          type="button"
          class="text-button"
          disabled={$syncPreview.working}
          on:click={() => (removing = device.deviceId)}
        >
          Remove
        </button>
      </li>
    {/each}
  </ul>
{/if}

<SyncEnableModal
  open={$syncPreview.enableOpen}
  working={$syncPreview.working}
  error={$syncPreview.error}
  onCancel={syncPreview.closeEnable}
  onEnable={syncPreview.enable}
/>
<SyncApproveDeviceModal
  open={$syncPreview.approveOpen}
  deviceLabel={$syncPreview.pendingLabel}
  fingerprint={$syncPreview.pendingFingerprint}
  requestedAt={$syncPreview.pendingRequestedAt}
  working={$syncPreview.working}
  error={$syncPreview.error}
  onDeny={syncPreview.denyDevice}
  onApprove={syncPreview.approveDevice}
/>
<SyncConflictModal
  open={$syncPreview.conflictOpen}
  thisDevice={$syncPreview.conflictThisDevice}
  otherDevice={$syncPreview.conflictOtherDevice}
  working={$syncPreview.working}
  error={$syncPreview.error}
  detailsLoaded={$syncPreview.conflictDetailsLoaded}
  detailsError={$syncPreview.conflictDetailsError}
  onCancel={syncPreview.closeConflict}
  onKeep={(choice) => void syncPreview.resolveConflict(choice)}
/>

<style>
  .sync-note {
    margin: var(--space-2) 0 0;
    color: var(--text-muted);
    font-size: var(--type-1);
    line-height: 1.5;
  }
  .sync-done {
    margin: var(--space-2) 0 0;
    color: var(--ok-text, var(--accent-link));
    font-size: var(--type-1);
    line-height: 1.5;
  }

  .sync-actions {
    display: flex;
    flex: none;
    align-items: center;
    gap: var(--space-3);
  }

  .sync-caution :global(.settings-icon) {
    color: var(--danger);
  }
  .sync-caution p {
    color: var(--danger);
  }

  .sync-own-code {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-4) 0;
    border-bottom: 1px solid var(--border-soft);
  }
  .sync-own-code strong {
    color: var(--text-heading);
    font-size: var(--type-2);
  }
  .sync-own-code p {
    margin: 0;
    color: var(--text-muted);
    font-size: var(--type-1);
    line-height: 1.5;
  }
  .sync-own-code code {
    justify-self: start;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    background: var(--surface-inset);
    color: var(--text-heading);
    font-family: var(--font-code);
    font-size: var(--type-3);
    letter-spacing: 0.08em;
  }
  .sync-own-code input {
    justify-self: start;
    width: min(100%, 22rem);
  }

  .sync-devices {
    display: grid;
    gap: var(--space-2);
    margin: var(--space-2) 0 0;
    padding: 0;
    list-style: none;
  }
  .sync-devices li {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
  .sync-device-label {
    flex: 1;
    min-width: 0;
    color: var(--text);
    font-size: var(--type-2);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sync-device-state {
    flex: none;
    color: var(--text-muted);
    font-size: var(--type-1);
  }
</style>

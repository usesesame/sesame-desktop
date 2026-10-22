<script lang="ts">
  import { onMount } from 'svelte'
  import SyncEnableModal from './SyncEnableModal.svelte'
  import SyncPairingModal from './SyncPairingModal.svelte'
  import SyncJoinModal from './SyncJoinModal.svelte'
  import SyncConflictModal from './SyncConflictModal.svelte'
  import { syncController as syncPanel } from '../sync'

  onMount(() => {
    void syncPanel.refresh()
  })

  const stateLabels: Record<string, string> = {
    not_enrolled: 'Not set up on this device',
    no_vault: 'Not set up',
    pairing: 'Waiting to be added',
    joining: 'Joining is paused',
    approved: 'Active',
    removed: 'Removed',
  }

  const statusMessages: Record<string, string> = {
    not_enrolled: 'Sync is not set up on this device',
    no_vault: 'This account has no synced vault yet',
    pairing: 'This device is waiting to join your synced vault',
    joining: 'Joining is paused and you can finish it here',
    approved: 'Sync is active and your vault is encrypted before it reaches the server',
    removed: 'This device was removed from your synced vault',
  }

  $: summary = statusMessages[$syncPanel.state] ?? 'Sesame could not read the Sync status'
  $: others = $syncPanel.devices.filter((device) => !device.isThisDevice && device.state === 'approved')

  let removing = ''
  let removalPassword = ''
  let keyPassword = ''
  let leaving = false
  let leavePassword = ''
  let showBackups = false

  $: coordinatorNote = describeCoordinator($syncPanel.coordinator)
  $: confirmation = describeConfirmation($syncPanel.state, $syncPanel.confirmedAt, others.length, $syncPanel.peerChecksSkipped)

  function describeConfirmation(state: string, confirmedAt: number, peers: number, skipped: boolean): string {
    if (state !== 'approved' || peers === 0) return ''
    if (skipped) return 'Sesame could not check what your other devices last saw, so it could not rule out an old copy of this vault. It checks again on the next sync.'
    if (confirmedAt === 0) return 'No other device has confirmed this vault yet.'
    return `Another device last confirmed this vault on ${new Date(confirmedAt * 1000).toLocaleString()}.`
  }

  function describeCoordinator(state: {
    phase: string
    halt: string
    consecutiveFailures: number
    lastSuccessRevision: number
  }): string {
    if (state.phase === 'paused') return 'Sync is paused while the vault is locked.'
    if (state.phase === 'halted') {
      switch (state.halt) {
        case 'revoked':
          return 'This device was removed from the vault. Turn Sync off here and join again with a code.'
        case 'not_entitled':
          return 'Your subscription does not cover Sesame Sync. You can still download and remove devices.'
        case 'incompatible':
          return 'Sesame Sync needs a newer version of this app.'
        case 'fork':
          return 'Your devices disagree about this vault. Sync is paused and nothing was changed here.'
        case 'conflict':
          return 'Two devices changed this vault. Choose which version to keep.'
        case 'locked':
          return 'Unlock Sesame to keep syncing.'
        default:
          return 'Sesame Sync stopped.'
      }
    }
    if (state.phase === 'gave_up') {
      return 'Sesame could not reach your sync server after several tries. It tries again every 30 minutes, and Sync now tries right away.'
    }
    if (state.phase === 'retrying') {
      return `Could not reach Sesame Sync. Trying again (${state.consecutiveFailures}).`
    }
    if (state.phase === 'working') return 'Syncing…'
    if (state.lastSuccessRevision > 0) return `Up to date at version ${state.lastSuccessRevision}.`
    return ''
  }

  async function confirmRemoval() {
    await syncPanel.removeDevice(removing, removalPassword)
    removalPassword = ''
    removing = ''
  }

  async function confirmKey() {
    await syncPanel.takeNewKey(keyPassword)
    keyPassword = ''
  }

  async function confirmLeave() {
    await syncPanel.leave(leavePassword, false)
    leavePassword = ''
    leaving = false
  }
</script>

<article class="sync-row">
  <div class="setting-copy">
    <strong>Sesame Sync</strong>
    <p role="status">{summary}.</p>
    {#if $syncPanel.alarm}
      <p class="sync-alarm" role="alert">
        {$syncPanel.alarm} Sync is paused and nothing was changed on this device.
      </p>
    {/if}
    {#if $syncPanel.loadError}
      <p class="sync-note">{$syncPanel.loadError}</p>
    {/if}
    {#if coordinatorNote}
      <p class="sync-note">{coordinatorNote}</p>
    {/if}
    {#if confirmation}
      <p class="sync-note">{confirmation}</p>
    {/if}
    {#if $syncPanel.lastTransfer}
      <p class="sync-done">{$syncPanel.lastTransfer}</p>
    {/if}
  </div>
  <div class="sync-actions">
    {#if $syncPanel.state === 'approved'}
      <button
        type="button"
        class="secondary-button settings-manage"
        disabled={$syncPanel.working || $syncPanel.needsNewKey}
        on:click={syncPanel.syncNow}
      >
        {$syncPanel.working ? 'Syncing…' : 'Sync now'}
      </button>
      <button
        type="button"
        class="secondary-button settings-manage"
        disabled={$syncPanel.working || $syncPanel.needsNewKey}
        on:click={syncPanel.openPairing}
      >
        Add a device
      </button>
    {:else if $syncPanel.state === 'no_vault'}
      <button
        type="button"
        class="secondary-button settings-manage"
        disabled={$syncPanel.working}
        on:click={syncPanel.openEnable}
      >
        Set up
      </button>
    {:else if $syncPanel.state === 'not_enrolled' || $syncPanel.state === 'pairing' || $syncPanel.state === 'joining'}
      <button
        type="button"
        class="secondary-button settings-manage"
        disabled={$syncPanel.working}
        on:click={syncPanel.openJoin}
      >
        {$syncPanel.state === 'joining' ? 'Finish joining' : 'Join with a code'}
      </button>
      {#if $syncPanel.state !== 'joining'}
      <button
        type="button"
        class="text-button"
        disabled={$syncPanel.working}
        on:click={syncPanel.openEnable}
      >
        Start a new synced vault
      </button>
      {/if}
    {:else if $syncPanel.state === 'removed'}
      <button
        type="button"
        class="secondary-button settings-manage"
        disabled={$syncPanel.working}
        on:click={() => syncPanel.leave('', true)}
      >
        Turn Sync off here
      </button>
    {/if}
    {#if $syncPanel.enrolled}
      <button
        type="button"
        class="text-button"
        disabled={$syncPanel.working}
        on:click={() => {
          showBackups = !showBackups
          if (showBackups) void syncPanel.loadBackups()
        }}
      >
        {showBackups ? 'Hide recovery copies' : 'Recovery copies'}
      </button>
    {/if}
    <button
      type="button"
      class="text-button"
      disabled={$syncPanel.working}
      on:click={syncPanel.refresh}
    >
      Refresh
    </button>
  </div>
</article>

<article class="sync-caution">
  <div class="setting-copy">
    <strong>Not independently reviewed</strong>
    <p>
      Sync has not had an independent security review. Keep backups while you try it.
    </p>
  </div>
</article>

{#if $syncPanel.needsNewKey}
  <div class="sync-own-code">
    <strong>Take the new vault key</strong>
    <p>
      A device was removed and the vault key changed. This device needs the new key before it can
      sync again. Enter your master password to continue and get a new recovery kit.
    </p>
    <input
      type="password"
      bind:value={keyPassword}
      placeholder="Master password"
      aria-label="Master password"
      autocomplete="current-password"
    />
    <div class="modal-actions">
      <button
        type="button"
        class="primary-button"
        disabled={!keyPassword || $syncPanel.working}
        on:click={confirmKey}
      >
        Take the new key
      </button>
    </div>
  </div>
{/if}
{#if $syncPanel.removalRecoveryKit}
  <div class="sync-own-code" role="status">
    <strong>Write down your new recovery kit</strong>
    <p>
      Save this kit now, because your vault key changed and your previous kit no longer works.
    </p>
    <code>{$syncPanel.removalRecoveryKit}</code>
    <button type="button" class="text-button" on:click={syncPanel.dismissRecoveryKit}>
      I have written it down
    </button>
  </div>
{/if}
{#if showBackups}
  <div class="sync-own-code">
    <strong>Recovery copies</strong>
    <p>
      Sesame saves a recovery copy before replacing a vault, and saves your current vault
      before you restore one.
    </p>
    {#if $syncPanel.backups.length === 0}
      <p>No recovery copies on this device.</p>
    {:else}
      <ul class="sync-devices">
        {#each $syncPanel.backups as backup (backup.name)}
          <li>
            <span class="sync-device-label">
              {backup.side === 'this-device' ? 'This device' : 'Other device'}, version
              {backup.revision}
            </span>
            <span class="sync-device-state">{backup.entryCount} logins</span>
            <button
              type="button"
              class="text-button"
              disabled={$syncPanel.working}
              on:click={() => syncPanel.restoreBackup(backup.name)}
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
      aria-label="Master password"
      autocomplete="current-password"
    />
    <div class="modal-actions">
      <button
        type="button"
        class="secondary-button"
        disabled={$syncPanel.working}
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
        disabled={!removalPassword || $syncPanel.working}
        on:click={confirmRemoval}
      >
        Remove device
      </button>
    </div>
  </div>
{/if}
{#if leaving}
  <div class="sync-own-code">
    <strong>Turn Sync off on this device</strong>
    <p>
      This device leaves the vault and the vault key changes for the devices that stay. Your local
      vault stays here. Enter your master password to confirm.
    </p>
    <input
      type="password"
      bind:value={leavePassword}
      placeholder="Master password"
      aria-label="Master password"
      autocomplete="current-password"
    />
    <div class="modal-actions">
      <button
        type="button"
        class="secondary-button"
        disabled={$syncPanel.working}
        on:click={() => {
          leaving = false
          leavePassword = ''
        }}
      >
        Cancel
      </button>
      <button
        type="button"
        class="primary-button"
        disabled={!leavePassword || $syncPanel.working}
        on:click={confirmLeave}
      >
        Turn Sync off
      </button>
    </div>
  </div>
{/if}
{#if $syncPanel.state === 'approved' && !leaving}
  <div class="sync-actions-row">
    <button type="button" class="text-button" disabled={$syncPanel.working} on:click={() => (leaving = true)}>
      Turn Sync off on this device
    </button>
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
          disabled={$syncPanel.working}
          on:click={() => (removing = device.deviceId)}
        >
          Remove
        </button>
      </li>
    {/each}
  </ul>
{/if}

<SyncEnableModal
  open={$syncPanel.enableOpen}
  working={$syncPanel.working}
  error={$syncPanel.error}
  onCancel={syncPanel.closeEnable}
  onEnable={syncPanel.enable}
/>
<SyncPairingModal
  open={$syncPanel.pairingOpen}
  code={$syncPanel.pairingCode}
  phase={$syncPanel.pairingPhase}
  secondsLeft={$syncPanel.pairingSecondsLeft}
  doneLabel={$syncPanel.pairingDone}
  error={$syncPanel.error}
  onClose={syncPanel.closePairing}
  onRetry={syncPanel.openPairing}
/>
<SyncJoinModal
  open={$syncPanel.joinOpen}
  working={$syncPanel.working}
  resuming={$syncPanel.state === 'joining'}
  error={$syncPanel.error}
  onCancel={syncPanel.closeJoin}
  onJoin={syncPanel.join}
/>
<SyncConflictModal
  open={$syncPanel.conflictOpen}
  thisDevice={$syncPanel.conflictThisDevice}
  otherDevice={$syncPanel.conflictOtherDevice}
  working={$syncPanel.working}
  error={$syncPanel.error}
  detailsLoaded={$syncPanel.conflictDetailsLoaded}
  detailsError={$syncPanel.conflictDetailsError}
  onCancel={syncPanel.closeConflict}
  onKeep={(choice) => void syncPanel.resolveConflict(choice)}
/>

<style>
  .sync-note {
    margin: var(--space-2) 0 0;
    color: var(--text-muted);
    font-size: var(--type-2);
    line-height: 1.5;
  }
  .sync-done {
    margin: var(--space-2) 0 0;
    color: var(--ok-text, var(--accent-link));
    font-size: var(--type-2);
    line-height: 1.5;
  }

  .sync-row {
    flex-wrap: wrap;
  }

  .sync-actions {
    display: flex;
    flex: 0 1 auto;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2) var(--space-3);
  }

  .sync-alarm {
    margin: var(--space-2) 0 0;
    color: var(--danger);
    font-size: var(--type-2);
    line-height: 1.5;
  }

  .sync-actions-row {
    padding: var(--space-2) 0;
  }

  .sync-own-code {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-4) 0;
    border-bottom: 1px solid var(--border-soft);
  }
  .sync-own-code strong {
    color: var(--text-heading);
    font-size: var(--type-3);
  }
  .sync-own-code p {
    margin: 0;
    color: var(--text-muted);
    font-size: var(--type-2);
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
    padding: 10px var(--space-3);
    border: 1px solid var(--field-border);
    border-radius: var(--radius-md);
    color: var(--text);
    background: var(--field-bg);
    font-size: var(--type-3);
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
    font-size: var(--type-3);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .sync-device-state {
    flex: none;
    color: var(--text-muted);
    font-size: var(--type-2);
  }
</style>

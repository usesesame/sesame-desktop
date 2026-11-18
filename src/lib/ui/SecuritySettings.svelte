<script lang="ts">
  import { slidingSelection } from './sliding-selection'
  import { platformCapabilities } from '../platform'
  import { MAX_PIN_DIGITS, MIN_PIN_DIGITS } from '../pin-rules'
  import type { RecoveryReplacementStatus } from '../types'
  import { recoveryRequestPending } from '../recovery-replacement'

  export let autoLockMinutes = 5
  export let autoLockOptions: number[] = []
  export let onSetAutoLockMinutes: (minutes: number) => void
  export let pinUnlockAvailable = false
  export let pinWorking = false
  export let onTogglePin: () => void
  export let helloUnlockAvailable = false
  export let helloWorking = false
  export let onToggleHello: () => void
  export let screenCaptureAllowed = false
  export let screenCaptureKnown = true
  export let screenCaptureWorking = false
  export let onToggleScreenCapture: () => void = () => {}
  export let clipboardClearSeconds = 30
  export let clipboardClearOptions: number[] = []
  export let onSetClipboardClearSeconds: (seconds: number) => void
  export let onChangeMasterPassword: () => void
  export let recoveryReplacement: RecoveryReplacementStatus | null = null
  export let recoveryWorking = false
  export let onRequestRecoveryKit: () => void = () => {}
  export let onIssueRecoveryKit: () => void = () => {}
  export let onCancelRecoveryRequest: () => void = () => {}

  function formatMoment(seconds: number | undefined): string {
    return seconds === undefined ? '' : new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  }

  $: recoveryRequested = recoveryRequestPending(recoveryReplacement)
</script>

<div class="settings-groups">
  <section class="settings-group" aria-labelledby="settings-group-security-device">
    <h3 id="settings-group-security-device">This device</h3>
    <div class="settings-list">
      {#if $platformCapabilities.sessionAutoLock}
      <article>
        <div class="setting-copy"><strong>Automatic lock</strong><p>{$platformCapabilities.systemIdle ? 'Lock the vault after a period without keyboard or pointer activity.' : 'Lock the vault after a period without keyboard or pointer activity in Sesame. This desktop does not report when you are idle, so work in other programs does not count.'}</p></div>
        <div class="auto-lock-options" role="group" aria-label="Automatic lock delay" use:slidingSelection>{#each autoLockOptions as minutes (minutes)}<button type="button" class:active={autoLockMinutes === minutes} aria-pressed={autoLockMinutes === minutes} aria-label={`${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`} on:click={() => onSetAutoLockMinutes(minutes)}>{minutes}m</button>{/each}</div>
      </article>
      {/if}
      {#if $platformCapabilities.os === 'linux' && !$platformCapabilities.screenLockMonitoring}
      <article>
        <div class="setting-copy"><strong>Screen lock</strong><p>Sesame cannot tell when this desktop locks its screen, so lock the vault yourself before you step away.</p></div>
      </article>
      {/if}
      {#if $platformCapabilities.pinUnlock}
      <article>
        <div class="setting-copy"><strong>Unlock with PIN</strong><p>Use a PIN of {MIN_PIN_DIGITS} to {MAX_PIN_DIGITS} digits on this device. Your master password or recovery kit remains available.</p></div>
        <button type="button" class="switch" class:active={pinUnlockAvailable} role="switch" aria-checked={pinUnlockAvailable} aria-label="Unlock with PIN" disabled={pinWorking} on:click={onTogglePin}><span></span></button>
      </article>
      {/if}
      {#if $platformCapabilities.biometricUnlock}
      <article>
        <div class="setting-copy"><strong>Unlock with Windows Hello</strong><p>Use this device's Windows Hello gesture. Your master password or recovery kit remains available, and Sesame never receives your biometric data.</p></div>
        <button type="button" class="switch" class:active={helloUnlockAvailable} role="switch" aria-checked={helloUnlockAvailable} aria-label="Unlock with Windows Hello" disabled={helloWorking} on:click={onToggleHello}><span></span></button>
      </article>
      {/if}
      {#if $platformCapabilities.os === 'windows'}
      <article>
        <div class="setting-copy"><strong>Allow screen capture</strong><p>Sesame asks Windows to keep its windows out of screenshots, screen sharing and Recall. Turn this on only while someone helps you in a support session.</p></div>
        <button type="button" class="switch" class:active={screenCaptureKnown && screenCaptureAllowed} role="switch" aria-checked={screenCaptureKnown ? screenCaptureAllowed : "mixed"} aria-label="Allow screen capture" disabled={screenCaptureWorking || !screenCaptureKnown} on:click={onToggleScreenCapture}><span></span></button>
      </article>
      {/if}
      <article>
        <div class="setting-copy"><strong>Clipboard timeout</strong><p>How long a copied password or code stays on the clipboard before Sesame clears it.</p></div>
        <div class="clipboard-clear-options" role="group" aria-label="Clipboard clear delay" use:slidingSelection>{#each clipboardClearOptions as seconds (seconds)}<button type="button" class:active={clipboardClearSeconds === seconds} aria-pressed={clipboardClearSeconds === seconds} aria-label={`${seconds} seconds`} on:click={() => onSetClipboardClearSeconds(seconds)}>{seconds}s</button>{/each}</div>
      </article>
    </div>
  </section>
  <section class="settings-group" aria-labelledby="settings-group-security-key">
    <h3 id="settings-group-security-key">Your vault key</h3>
    <div class="settings-list">
      <article>
        <div class="setting-copy"><strong>Master password</strong><p>Replace your master password and get a fresh recovery kit.</p></div>
        <button type="button" class="secondary-button settings-manage" on:click={onChangeMasterPassword}>Change</button>
      </article>
      <article>
        {#if recoveryRequested && recoveryReplacement?.ready}
          <div class="setting-copy"><strong>Recovery kit</strong><p>The new recovery kit you requested on {formatMoment(recoveryReplacement.requestedAt)} is ready. Getting it replaces your current kit.</p></div>
          <div class="diagnostic-actions"><button type="button" class="text-button" disabled={recoveryWorking} on:click={onCancelRecoveryRequest}>Cancel request</button><button type="button" class="secondary-button settings-manage" disabled={recoveryWorking} on:click={onIssueRecoveryKit}>Get new kit</button></div>
        {:else if recoveryRequested}
          <div class="setting-copy"><strong>Recovery kit</strong><p class="recovery-request-warning">A new recovery kit was requested on {formatMoment(recoveryReplacement?.requestedAt)}. It is ready on {formatMoment(recoveryReplacement?.availableAt)}. If you did not ask for this, cancel it and change your master password.</p>{#if !recoveryReplacement?.timeConfirmed}<p>Sesame needs two independent servers to agree on the time before it issues the kit. Connect to the internet to get it.</p>{/if}</div>
          <button type="button" class="secondary-button settings-manage" disabled={recoveryWorking} on:click={onCancelRecoveryRequest}>Cancel request</button>
        {:else}
          <div class="setting-copy"><strong>Recovery kit</strong><p>Lost your recovery kit? Request a new one with your master password. It is ready 72 hours later, and Sesame warns on every unlock until then. Sesame measures the wait with servers on the internet, not this computer's clock, and it needs two of them to agree.</p></div>
          <button type="button" class="secondary-button settings-manage" disabled={recoveryWorking} on:click={onRequestRecoveryKit}>Request new kit</button>
        {/if}
      </article>
    </div>
  </section>
</div>

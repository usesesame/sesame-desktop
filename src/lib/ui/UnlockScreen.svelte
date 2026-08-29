<script lang="ts">
  import { onMount, tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import SetupProgress from './SetupProgress.svelte'
  import type { VaultStatus } from '../types'
  import { platformCapabilities } from '../platform'

  const PIN_LENGTH = 6

  export let status: VaultStatus
  export let recoveryUnlockOpen = false
  export let masterPassword = ''
  export let unlockPin = ''
  export let confirmPassword = ''
  export let errorMessage = ''
  export let isWorking = false
  export let restoreMessage = ''
  export let onUnlockWithPin: () => void
  export let onUnlockWithHello: () => void
  export let onSubmitMasterPassword: () => void

  let pinField: HTMLInputElement
  let pinSubmitted = false
  let masterPasswordInput: HTMLInputElement

  $: pinDigits = Array.from({ length: PIN_LENGTH }, (_, index) => unlockPin[index] ?? '')

  function onPinInput(event: Event) {
    const field = event.currentTarget as HTMLInputElement
    const digits = field.value.replace(/\D/g, '').slice(0, PIN_LENGTH)
    if (field.value !== digits) field.value = digits
    unlockPin = digits
    errorMessage = ''
  }

  $: if (pinField && pinField.value !== unlockPin) pinField.value = unlockPin

  function focusPin() {
    pinField?.focus()
  }

  async function openRecovery() {
    recoveryUnlockOpen = true
    errorMessage = ''
    masterPassword = ''
    unlockPin = ''
    await tick()
    masterPasswordInput?.focus()
  }

  async function closeRecovery() {
    recoveryUnlockOpen = false
    errorMessage = ''
    masterPassword = ''
    await tick()
    if (showPin) focusPin()
    else masterPasswordInput?.focus()
  }

  $: showPin = status.exists && status.pinUnlockAvailable && $platformCapabilities.pinUnlock && !recoveryUnlockOpen
  $: showHello = status.exists && status.helloUnlockAvailable && $platformCapabilities.biometricUnlock && !recoveryUnlockOpen
  $: if (unlockPin.length < PIN_LENGTH) pinSubmitted = false
  $: if (showPin && unlockPin.length === PIN_LENGTH && !isWorking && !pinSubmitted) {
    pinSubmitted = true
    onUnlockWithPin()
  }

  onMount(async () => {
    await tick()
    if (showPin) focusPin()
    else masterPasswordInput?.focus()
  })
</script>

<main class="welcome-shell" class:pin-unlock={showPin}>
  <section class="unlock-card" aria-labelledby="unlock-heading" aria-busy={isWorking}>
    <div class="card-topline"><span>{status.exists ? 'Unlock Sesame' : 'Set up Sesame'}</span>{#if !status.exists}<SetupProgress step={1} />{:else}<span class="beta-chip">BETA</span>{/if}</div>
    <h1 id="unlock-heading">{!status.exists ? 'Create your vault.' : recoveryUnlockOpen ? 'Use another unlock method.' : showPin ? 'Enter your PIN' : 'Enter your master password'}</h1>
    {#if !showPin}<p>{!status.exists ? 'Choose a master password. You will get a one-time recovery kit to write down.' : recoveryUnlockOpen ? 'Enter the master password or the recovery kit for this vault.' : 'This vault opens with the master password you chose.'}</p>{/if}
    {#if restoreMessage}<div class="restore-success" role="status"><Icon name="check" size={16} /><span>{restoreMessage}</span></div>{/if}

    {#if showHello}
      <button type="button" class="secondary-button full hello-unlock" disabled={isWorking} on:click={onUnlockWithHello}>
        <Icon name="shield" size={16} /> Unlock with Windows Hello
      </button>
    {/if}

    {#if showPin}
      <form novalidate on:submit|preventDefault={onUnlockWithPin}>
        <div class="pin-field">
          <input
            bind:this={pinField}
            class="pin-entry"
            name="unlock-pin"
            type="password"
            inputmode="numeric"
            autocomplete="off"
            spellcheck="false"
            maxlength={PIN_LENGTH}
            disabled={isWorking}
            aria-label="Six-digit PIN"
            aria-invalid={Boolean(errorMessage)}
            aria-describedby={errorMessage ? 'unlock-error' : undefined}
            on:input={onPinInput}
          />
          {#each pinDigits as digit, index (index)}
            <span class="pin-cell" class:filled={digit !== ''} class:next={index === unlockPin.length} aria-hidden="true"></span>
          {/each}
        </div>
        {#if errorMessage}
          <p id="unlock-error" class="form-error" role="alert">{errorMessage}</p>
        {:else if isWorking}
          <p class="pin-status" role="status">Unlocking…</p>
        {/if}
      </form>
      <button type="button" class="text-button unlock-alternative" on:click={openRecovery}>Use master password or recovery kit</button>
    {:else}
      <form on:submit|preventDefault={onSubmitMasterPassword}>
        <label for="master-password">{recoveryUnlockOpen ? 'Master password or recovery kit' : 'Master password'}</label>
        <input bind:this={masterPasswordInput} id="master-password" name="master-password" type="password" bind:value={masterPassword} autocomplete={recoveryUnlockOpen ? 'off' : status.exists ? 'current-password' : 'new-password'} spellcheck="false" aria-invalid={Boolean(errorMessage)} aria-describedby={errorMessage ? 'unlock-error' : undefined} />
        {#if !status.exists}
          <label for="confirm-password">Confirm master password</label>
          <input id="confirm-password" name="confirm-password" type="password" bind:value={confirmPassword} autocomplete="new-password" />
        {/if}
        {#if errorMessage}<p id="unlock-error" class="form-error" role="alert">{errorMessage}</p>{/if}
        <button class="primary-button full" type="submit" disabled={isWorking}>
          {status.exists ? 'Unlock vault' : 'Create local vault'}
        </button>
        {#if status.exists && recoveryUnlockOpen}
          <button type="button" class="text-button unlock-alternative" on:click={closeRecovery}>{status.pinUnlockAvailable ? 'Use PIN instead' : 'Go back'}</button>
        {:else if status.exists && !status.pinUnlockAvailable}
          <button type="button" class="text-button unlock-alternative" on:click={openRecovery}>Use recovery kit instead</button>
        {/if}
      </form>
    {/if}
    {#if status.preview}
      <p class="tiny-note">Browser preview only. No vault file is created here.</p>
    {:else if !status.exists}
      <p class="tiny-note">Keep an encrypted backup somewhere safe.</p>
    {/if}
  </section>
</main>

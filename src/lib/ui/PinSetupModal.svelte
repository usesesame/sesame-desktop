<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'
  import SetupProgress from './SetupProgress.svelte'

  export let pin = ''
  export let confirmPin = ''
  export let errorMessage = ''
  export let working = false
  export let onCancel: () => void
  export let onSave: () => void
  export let onEdit: () => void = () => {}
  export let setupStep = 0

  $: pinsComplete = pin.length === 6 && confirmPin.length === 6
  $: pinsMatch = pin === confirmPin
  $: showMismatch = confirmPin.length === 6 && !pinsMatch

  function inputDigits(event: Event) {
    const input = event.currentTarget as HTMLInputElement
    const value = input.value.replace(/\D/g, '').slice(0, 6)
    input.value = value
    onEdit()
    return value
  }

  function updatePin(event: Event) {
    pin = inputDigits(event)
  }

  function updateConfirmation(event: Event) {
    confirmPin = inputDigits(event)
  }
</script>

<ModalShell
  open={true}
  onClose={() => { if (!working) onCancel() }}
  labelledby="pin-setup-heading"
  describedby="pin-setup-description"
  tone="pin-setup"
  modalClass="pin-setup-modal"
  ariaBusy={working}
>
  <div class="setup-head">
    <span class="confirm-icon"><Icon name="key" size={20} /></span>
    {#if setupStep}<SetupProgress step={setupStep} />{/if}
  </div>
  <h2 id="pin-setup-heading">Set a PIN</h2>
  <p id="pin-setup-description">Use six digits for everyday unlock on this device. Your master password or recovery kit remains the fallback.</p>
  <form novalidate on:submit|preventDefault={onSave}>
    <label for="unlock-pin">PIN</label>
    <input id="unlock-pin" type="password" inputmode="numeric" maxlength="6" autocomplete="new-password" value={pin} on:input={updatePin} />
    <label for="confirm-unlock-pin">Confirm PIN</label>
    <input id="confirm-unlock-pin" type="password" inputmode="numeric" maxlength="6" autocomplete="new-password" value={confirmPin} aria-invalid={showMismatch} aria-describedby={showMismatch || errorMessage ? 'pin-setup-error' : undefined} on:input={updateConfirmation} />
    {#if showMismatch}<p id="pin-setup-error" class="form-error" role="alert">Those PINs do not match.</p>
    {:else if errorMessage}<p id="pin-setup-error" class="form-error" role="alert">{errorMessage}</p>{/if}
    <p class="pin-security-note"><Icon name="monitor" size={15} /><span>The PIN is combined with a random secret protected by Windows before it wraps your vault key.</span></p>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={onCancel}>Not now</button>
      <button type="submit" class="primary-button" disabled={working || !pinsComplete || !pinsMatch}>{working ? 'Saving…' : 'Save PIN'}</button>
    </div>
  </form>
</ModalShell>

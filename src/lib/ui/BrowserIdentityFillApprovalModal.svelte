<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { BrowserIdentityFillRequest, IdentityFieldKey } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserIdentityFillRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const FIELD_LABELS: Record<IdentityFieldKey, string> = {
    fullName: 'Name',
    email: 'Email',
    phone: 'Phone',
    addressLine1: 'Address',
    addressLine2: 'Address (second line)',
    city: 'City',
    region: 'Region',
    postalCode: 'Postal code',
    country: 'Country',
  }

  const { browserIdentityFill } = useAppStores()
  const remainingSeconds = () => Math.max(0, Math.ceil((request.expiresAtUnixMs - Date.now()) / 1_000))
  let remaining = remainingSeconds()
  let expired = false
  const timer = window.setInterval(() => {
    remaining = remainingSeconds()
    if (remaining === 0 && !expired) {
      expired = true
      onCancel()
    }
  }, 1_000)

  onDestroy(() => window.clearInterval(timer))

  function cancel() {
    if (!working) onCancel()
  }
</script>

<ModalShell
  open={true}
  onClose={cancel}
  labelledby="browser-identity-heading"
  describedby="browser-identity-description"
  tone="browser-fill"
  modalClass="browser-fill-modal"
  ariaBusy={working}
>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <p class="eyebrow">Fill in browser</p>
  <h2 id="browser-identity-heading">Fill {request.hostname}?</h2>
  <p id="browser-identity-description">Choose the saved identity to use. Only the fields below are filled, and the form is not submitted.</p>

  <div class="browser-fill-origin">
    <Icon name="shield" size={15} />
    <span>Requesting page</span>
    <code>{request.origin}</code>
  </div>

  <div class="browser-fill-origin identity-fields-requested">
    <Icon name="check" size={15} />
    <span>Fields requested</span>
    <code>{request.requestedFields.map((field) => FIELD_LABELS[field] ?? field).join(', ')}</code>
  </div>

  <div class="browser-fill-candidates" role="radiogroup" aria-label="Identities for {request.hostname}">
    {#each request.candidates as candidate (candidate.id)}
      <label class:selected={$browserIdentityFill.selectedId === candidate.id}>
        <input type="radio" name="browser-identity-choice" value={candidate.id} checked={$browserIdentityFill.selectedId === candidate.id} on:change={() => browserIdentityFill.patch({ selectedId: candidate.id })} disabled={working} />
        <span class="entry-avatar">{candidate.label.slice(0, 1).toUpperCase() || '?'}</span>
        <span><strong>{candidate.label}</strong></span>
      </label>
    {/each}
  </div>

  <div class="browser-fill-footer">
    <span>{remaining > 0 ? `Expires in ${remaining}s` : 'Request expired'}</span>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={cancel}>Not now</button>
      <button type="button" class="primary-button" disabled={!$browserIdentityFill.selectedId || working || remaining === 0} on:click={onConfirm}>
        {working ? 'Approving…' : 'Fill identity'}
      </button>
    </div>
  </div>
</ModalShell>

<style>
  .identity-fields-requested code { white-space: normal; }
</style>

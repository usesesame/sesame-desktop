<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { BrowserCardFillRequest, CardFieldKey } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserCardFillRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const FIELD_LABELS: Record<CardFieldKey, string> = {
    cardholderName: 'Cardholder name', number: 'Card number', expiryMonth: 'Expiry month', expiryYear: 'Expiry year', securityCode: 'Security code',
  }
  const { browserCardFill } = useAppStores()
  const remainingSeconds = () => Math.max(0, Math.ceil((request.expiresAtUnixMs - Date.now()) / 1_000))
  let remaining = remainingSeconds()
  let expired = false
  const timer = window.setInterval(() => {
    remaining = remainingSeconds()
    if (remaining === 0 && !expired) { expired = true; onCancel() }
  }, 1_000)
  onDestroy(() => window.clearInterval(timer))
  const cancel = () => { if (!working) onCancel() }
</script>

<ModalShell open={true} onClose={cancel} labelledby="browser-card-heading" describedby="browser-card-description" tone="browser-fill" modalClass="browser-fill-modal" ariaBusy={working}>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <p class="eyebrow">Fill card in browser</p>
  <h2 id="browser-card-heading">Fill {request.hostname}?</h2>
  <p id="browser-card-description">Choose a saved card. Every card fill needs this confirmation, and Sesame does not submit the form.</p>
  <div class="browser-fill-origin"><Icon name="shield" size={15} /><span>Requesting page</span><code>{request.origin}</code></div>
  <div class="browser-fill-origin"><Icon name="check" size={15} /><span>Fields requested</span><code>{request.requestedFields.map((field) => FIELD_LABELS[field] ?? field).join(', ')}</code></div>
  <div class="browser-fill-candidates" role="radiogroup" aria-label="Cards for {request.hostname}">
    {#each request.candidates as candidate (candidate.id)}
      <label class:selected={$browserCardFill.selectedId === candidate.id}>
        <input type="radio" name="browser-card-choice" value={candidate.id} checked={$browserCardFill.selectedId === candidate.id} on:change={() => browserCardFill.patch({ selectedId: candidate.id })} disabled={working} />
        <span class="entry-avatar">{candidate.brand.slice(0, 1).toUpperCase() || 'C'}</span>
        <span><strong>{candidate.title}</strong><small>{candidate.brand || 'Card'}{candidate.lastFour ? ` •••• ${candidate.lastFour}` : ''}</small></span>
      </label>
    {/each}
  </div>
  <div class="browser-fill-footer"><span>{remaining > 0 ? `Expires in ${remaining}s` : 'Request expired'}</span><div class="confirm-actions"><button type="button" class="secondary-button" disabled={working} on:click={cancel}>Cancel</button><button type="button" class="primary-button" disabled={!$browserCardFill.selectedId || working || remaining === 0} on:click={onConfirm}>{working ? 'Approving…' : 'Fill card'}</button></div></div>
</ModalShell>

<style>
  small { display: block; margin-top: 2px; color: var(--text-muted); }
  .browser-fill-origin code { white-space: normal; }
</style>

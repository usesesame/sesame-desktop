<script lang="ts">
  import { onDestroy } from 'svelte'
  import { approvalFooterText, approvalWait } from '../approval-wait'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { BrowserTotpFillRequest } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserTotpFillRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const { browserTotpFill } = useAppStores()
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
  labelledby="browser-totp-heading"
  describedby="browser-totp-description"
  tone="browser-fill"
  modalClass="browser-fill-modal"
  ariaBusy={working}
>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <h2 id="browser-totp-heading">Fill a one-time code on {request.hostname}?</h2>
  <p id="browser-totp-description">Choose the saved login whose code fills this form. Sesame inserts the code into the page, it is not copied to the clipboard, and it expires with the time window.</p>

  <div class="browser-fill-origin">
    <Icon name="shield" size={15} />
    <span>Requesting page</span>
    <code>{request.origin}</code>
  </div>

  <div class="browser-fill-candidates" role="radiogroup" aria-label="Logins for {request.hostname}">
    {#each request.candidates as candidate (candidate.id)}
      <label class:selected={$browserTotpFill.selectedId === candidate.id}>
        <input type="radio" name="browser-totp-choice" value={candidate.id} checked={$browserTotpFill.selectedId === candidate.id} on:change={() => browserTotpFill.patch({ selectedId: candidate.id })} disabled={working} />
        <span class="entry-avatar">{(candidate.title || candidate.username).slice(0, 1).toUpperCase() || '?'}</span>
        <span><strong>{candidate.title || candidate.username}</strong>{#if candidate.username}<small>{candidate.username}</small>{/if}</span>
      </label>
    {/each}
  </div>

  <div class="browser-fill-footer">
    <span>{approvalFooterText(remaining, $approvalWait)}</span>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={cancel}>Not now</button>
      <button type="button" class="primary-button" disabled={!$browserTotpFill.selectedId || working || remaining === 0 || $approvalWait.ms > 0} on:click={onConfirm}>
        {working ? 'Approving…' : 'Fill code'}
      </button>
    </div>
  </div>
</ModalShell>

<style>
  small { display: block; margin-top: 2px; color: var(--text-muted); }
  .browser-fill-origin code { white-space: normal; }
</style>

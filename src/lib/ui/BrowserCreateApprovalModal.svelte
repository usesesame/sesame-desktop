<script lang="ts">
  import { onDestroy } from 'svelte'
  import { approvalFooterText, approvalWait } from '../approval-wait'
  import Icon from '../Icon.svelte'
  import type { BrowserCreateRequest } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserCreateRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

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
  labelledby="browser-create-heading"
  describedby="browser-create-description"
  tone="browser-fill"
  modalClass="browser-fill-modal"
  ariaBusy={working}
>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <h2 id="browser-create-heading">Create a login for {request.hostname}?</h2>
  <p id="browser-create-description">Sesame makes a password, fills it in and saves a new login now.</p>

  <div class="browser-fill-origin">
    <Icon name="shield" size={15} />
    <span>Requesting page</span>
    <code>{request.origin}</code>
  </div>

  <div class="browser-fill-footer">
    <span>{approvalFooterText(remaining, $approvalWait)}</span>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={cancel}>Not now</button>
      <button type="button" class="primary-button" disabled={working || remaining === 0 || $approvalWait.ms > 0} on:click={onConfirm}>
        {working ? 'Creating…' : 'Create login'}
      </button>
    </div>
  </div>
</ModalShell>

<script lang="ts">
  import { settleKeyFor } from '../controllers/approval-gate'
  import { vaultText } from '../vault-text'
  import { onDestroy } from 'svelte'
  import { approvalFooterText, approvalWait } from '../approval-wait'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { BrowserChangeRequest } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserChangeRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const { browserChange } = useAppStores()
  const remainingSeconds = () => Math.max(0, Math.ceil((request.expiresAtUnixMs - Date.now()) / 1_000))
  let remaining = remainingSeconds()
  let expired = false
  $: selectedCandidate = request.candidates.find((candidate) => candidate.id === $browserChange.selectedId)
  $: selectedWaiting = selectedCandidate ? request.unconfirmed.includes(selectedCandidate.id) : false
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
  approval
  let:settled
  settleKey={settleKeyFor(request, $browserChange.selectedId)}
  open={true}
  onClose={cancel}
  labelledby="browser-change-heading"
  describedby="browser-change-description"
  tone="browser-fill"
  modalClass="browser-fill-modal"
  ariaBusy={working}
>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <h2 id="browser-change-heading">Change the password for {request.hostname}?</h2>
  <p id="browser-change-description">Sesame fills your current password and saves a new one to this login. The old one stays in history.</p>

  <div class="browser-fill-origin">
    <Icon name="shield" size={15} />
    <span>Requesting page</span>
    <code><bdi>{vaultText(request.origin)}</bdi></code>
  </div>

  {#if selectedWaiting}
    <div class="browser-fill-alias">
      <Icon name="alert" size={16} />
      <p><strong>An earlier change is not confirmed</strong><span>The site may still have the older password.</span></p>
    </div>
  {:else if selectedCandidate?.matchKind === 'site'}
    <div class="browser-fill-alias">
      <Icon name="alert" size={16} />
      <p><strong>Matched by site</strong><span>This login is saved for <code><bdi>{vaultText(selectedCandidate.savedOrigin)}</bdi></code> and set to fill on the whole site.</span></p>
    </div>
  {/if}

  <div class="browser-fill-candidates" role="radiogroup" aria-label="Logins for {request.hostname}">
    {#each request.candidates as candidate (candidate.id)}
      <label class:selected={$browserChange.selectedId === candidate.id}>
        <input type="radio" name="browser-change-login" value={candidate.id} checked={$browserChange.selectedId === candidate.id} on:change={() => browserChange.patch({ selectedId: candidate.id })} disabled={working} />
        <span class="entry-avatar">{vaultText(candidate.title).slice(0, 1).toUpperCase() || '?'}</span>
        <span class="candidate-text"><strong><bdi>{vaultText(candidate.title)}</bdi></strong><small><bdi>{vaultText(candidate.username || candidate.email) || 'No username saved'}</bdi></small><small class="candidate-origin"><bdi>{vaultText(candidate.savedOrigin)}</bdi></small></span>
        {#if candidate.matchKind === 'wwwAlias'}<span class="candidate-match">www match</span>{:else if candidate.matchKind === 'site'}<span class="candidate-match">Site match</span>{/if}
      </label>
    {/each}
  </div>

  <div class="browser-fill-footer">
    <span>{approvalFooterText(remaining, $approvalWait)}</span>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={cancel}>Not now</button>
      <button type="button" class="primary-button" disabled={!$browserChange.selectedId || working || remaining === 0 || $approvalWait.ms > 0 || !settled} on:click={onConfirm}>
        {working ? 'Changing…' : 'Change password'}
      </button>
    </div>
  </div>
</ModalShell>

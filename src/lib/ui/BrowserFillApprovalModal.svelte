<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { BrowserFillRequest } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserFillRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const { browserFill } = useAppStores()
  const remainingSeconds = () => Math.max(0, Math.ceil((request.expiresAtUnixMs - Date.now()) / 1_000))
  let remaining = remainingSeconds()
  let expired = false
  $: selectedCandidate = request.candidates.find((candidate) => candidate.id === $browserFill.selectedId)
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
  labelledby="browser-fill-heading"
  describedby="browser-fill-description"
  tone="browser-fill"
  modalClass="browser-fill-modal"
  ariaBusy={working}
>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <p class="eyebrow">Fill in browser</p>
  <h2 id="browser-fill-heading">Fill {request.hostname}?</h2>
  <p id="browser-fill-description">Choose the login to use. The fields will be filled, but the form is not submitted.</p>

  <div class="browser-fill-origin">
    <Icon name="shield" size={15} />
    <span>Requesting page</span>
    <code>{request.origin}</code>
  </div>

  {#if selectedCandidate?.matchKind === 'wwwAlias'}
    <div class="browser-fill-alias">
      <Icon name="alert" size={16} />
      <p><strong>Saved without "www"</strong><span>This login is saved for <code>{selectedCandidate.savedOrigin}</code>. The <code>www</code> address is treated as the same site.</span></p>
    </div>
  {/if}

  <div class="browser-fill-candidates" role="radiogroup" aria-label="Logins for {request.hostname}">
    {#each request.candidates as candidate (candidate.id)}
      <label class:selected={$browserFill.selectedId === candidate.id}>
        <input type="radio" name="browser-fill-login" value={candidate.id} checked={$browserFill.selectedId === candidate.id} on:change={() => browserFill.patch({ selectedId: candidate.id })} disabled={working} />
        <span class="entry-avatar">{candidate.title.slice(0, 1).toUpperCase() || '?'}</span>
        <span><strong>{candidate.title}</strong><small>{candidate.username || candidate.email || 'No username saved'}</small><small class="candidate-origin">{candidate.savedOrigin}</small></span>
        {#if candidate.matchKind === 'wwwAlias'}<span class="candidate-match">www match</span>{/if}
      </label>
    {/each}
  </div>

  <label class="browser-fill-remember">
    <input type="checkbox" bind:checked={$browserFill.remember} disabled={working} />
    <span><strong>Fill this login here without asking for 15 minutes</strong><small>Applies to {request.hostname} and this login only. Sesame forgets it when the vault locks or changes, and it is never saved to disk.</small></span>
  </label>

  <div class="browser-fill-footer">
    <span>{remaining > 0 ? `Expires in ${remaining}s` : 'Request expired'}</span>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={cancel}>Not now</button>
      <button type="button" class="primary-button" disabled={!$browserFill.selectedId || working || remaining === 0} on:click={onConfirm}>
        {working ? 'Approving…' : 'Fill login'}
      </button>
    </div>
  </div>
</ModalShell>

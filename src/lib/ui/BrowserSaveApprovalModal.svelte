<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { BrowserSaveRequest } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let request: BrowserSaveRequest
  export let working = false
  export let onCancel: () => void
  export let onConfirm: () => void

  const { browserSave } = useAppStores()
  const remainingSeconds = () => Math.max(0, Math.ceil((request.expiresAtUnixMs - Date.now()) / 1_000))
  let remaining = remainingSeconds()
  let expired = false
  $: isUpdate = request.kind === 'update'
  $: needsChoice = isUpdate && request.candidates.length > 1
  $: selectedCandidate = request.candidates.find((candidate) => candidate.id === $browserSave.selectedId)
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
  labelledby="browser-save-heading"
  describedby="browser-save-description"
  tone="browser-fill"
  modalClass="browser-fill-modal"
  ariaBusy={working}
>
  <span class="confirm-icon browser"><Icon name="browser" size={20} /></span>
  <p class="eyebrow">{isUpdate ? 'Update from browser' : 'Save from browser'}</p>
  <h2 id="browser-save-heading">{isUpdate ? 'Update this login?' : 'Save this login?'}</h2>
  <p id="browser-save-description">
    {#if isUpdate}
      Sesame noticed a changed password for {request.hostname}. Nothing changes until you approve it here.
    {:else}
      Sesame noticed a new sign-in for {request.hostname}. Nothing is stored until you approve it here.
    {/if}
  </p>

  <div class="browser-fill-origin">
    <Icon name="shield" size={15} />
    <span>Requesting page</span>
    <code>{request.origin}</code>
  </div>

  {#if isUpdate && needsChoice}
    <p class="tiny-note">More than one saved login matches this site. Choose which one to update.</p>
    <div class="browser-fill-candidates" role="radiogroup" aria-label="Saved logins for {request.hostname}">
      {#each request.candidates as candidate (candidate.id)}
        <label class:selected={$browserSave.selectedId === candidate.id}>
          <input type="radio" name="browser-save-update-target" value={candidate.id} checked={$browserSave.selectedId === candidate.id} on:change={() => browserSave.patch({ selectedId: candidate.id })} disabled={working} />
          <span class="entry-avatar">{candidate.title.slice(0, 1).toUpperCase() || '?'}</span>
          <span><strong>{candidate.title}</strong><small>{candidate.username || candidate.email || 'No username saved'}</small></span>
        </label>
      {/each}
    </div>
  {:else if isUpdate && selectedCandidate}
    <div class="browser-save-proposal">
      <span class="entry-avatar">{selectedCandidate.title.slice(0, 1).toUpperCase() || '?'}</span>
      <span><strong>{selectedCandidate.title}</strong><small>{selectedCandidate.username || selectedCandidate.email || 'No username saved'}</small></span>
    </div>
  {:else}
    <div class="browser-save-proposal">
      <span class="entry-avatar">{request.title.slice(0, 1).toUpperCase() || '?'}</span>
      <span><strong>{request.title}</strong><small>{request.username || 'No username captured'}</small></span>
    </div>
  {/if}

  <div class="browser-fill-footer">
    <span>{remaining > 0 ? `Expires in ${remaining}s` : 'Request expired'}</span>
    <div class="confirm-actions">
      <button type="button" class="secondary-button" disabled={working} on:click={cancel}>Discard</button>
      <button
        type="button"
        class="primary-button"
        disabled={working || remaining === 0 || (needsChoice && !$browserSave.selectedId)}
        on:click={onConfirm}
      >
        {working ? (isUpdate ? 'Updating…' : 'Saving…') : isUpdate ? 'Update login' : 'Save login'}
      </button>
    </div>
  </div>
</ModalShell>

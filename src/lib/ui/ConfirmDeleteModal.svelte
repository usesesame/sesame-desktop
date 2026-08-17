<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'
  import type { CleanupEntry } from '../types'

  export let deleteCandidate: CleanupEntry | null
  export let deleteBatch: CleanupEntry[] = []
  export let cleanupWorking = false
  export let onCancel: () => void
  export let onConfirm: () => void

  $: count = Math.max(1, deleteBatch.length)
  $: bulk = count > 1

  function cancel() {
    if (!cleanupWorking) onCancel()
  }
</script>

{#if deleteCandidate}
  <ModalShell
    open={true}
    onClose={cancel}
    labelledby="delete-login-heading"
    describedby="delete-login-description"
    tone="cleanup-confirm"
    modalClass="cleanup-confirm-modal"
    ariaBusy={cleanupWorking}
  >
    <span class="confirm-icon danger"><Icon name="alert" size={20} /></span>
    <h2 id="delete-login-heading">{bulk ? `Delete ${count} logins?` : `Delete ${deleteCandidate.title}?`}</h2>
    <p id="delete-login-description">This removes the {bulk ? 'logins' : 'login'}, {bulk ? 'their' : 'its'} password, 2FA secret, and recovery details from your vault.</p>
    {#if bulk}
      <ul class="confirm-list">
        {#each deleteBatch as target (target.id)}
          <li><span class="entry-avatar">{target.initials || target.title.slice(0, 1)}</span><div><strong>{target.title}</strong><span>{target.site || 'No website'}</span></div></li>
        {/each}
      </ul>
    {:else}
      <div class="confirm-entry"><span class="entry-avatar">{deleteCandidate.initials || deleteCandidate.title.slice(0, 1)}</span><div><strong>{deleteCandidate.title}</strong><span>{deleteCandidate.username || 'No username'}{deleteCandidate.site ? ` · ${deleteCandidate.site}` : ''}</span></div></div>
    {/if}
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={cleanupWorking} on:click={cancel}>Cancel</button><button type="button" class="danger-button" disabled={cleanupWorking} on:click={onConfirm}>{cleanupWorking ? 'Deleting…' : bulk ? `Delete ${count} logins` : 'Delete login'}</button></div>
  </ModalShell>
{/if}

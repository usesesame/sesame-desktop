<script lang="ts">
  import { vaultText } from '../vault-text'
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
    <h2 id="delete-login-heading">{#if bulk}Delete {count} logins?{:else}Delete <bdi>{vaultText(deleteCandidate.title)}</bdi>?{/if}</h2>
    <p id="delete-login-description">This removes the {bulk ? 'logins' : 'login'}, {bulk ? 'their' : 'its'} password, 2FA secret, and recovery details from your vault. {bulk ? 'They stay' : 'It stays'} in Trash for 30 days.</p>
    {#if bulk}
      <ul class="confirm-list">
        {#each deleteBatch as target (target.id)}
          <li><span class="entry-avatar">{target.initials || target.title.slice(0, 1)}</span><div><strong><bdi>{vaultText(target.title)}</bdi></strong><span><bdi>{vaultText(target.site) || 'No website'}</bdi></span></div></li>
        {/each}
      </ul>
    {:else}
      <div class="confirm-entry"><span class="entry-avatar">{deleteCandidate.initials || deleteCandidate.title.slice(0, 1)}</span><div><strong><bdi>{vaultText(deleteCandidate.title)}</bdi></strong><span><bdi>{vaultText(deleteCandidate.username) || 'No username'}</bdi>{#if deleteCandidate.site} · <bdi>{vaultText(deleteCandidate.site)}</bdi>{/if}</span></div></div>
    {/if}
    <div class="confirm-actions"><button type="button" class="secondary-button" disabled={cleanupWorking} on:click={cancel}>Cancel</button><button type="button" class="danger-button" disabled={cleanupWorking} on:click={onConfirm}>{cleanupWorking ? 'Deleting…' : bulk ? `Delete ${count} logins` : 'Delete login'}</button></div>
  </ModalShell>
{/if}

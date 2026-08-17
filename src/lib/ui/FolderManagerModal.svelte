<script lang="ts">
  import Icon from '../Icon.svelte'
  import type { Folder, VaultEntry } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let folders: Folder[] = []
  export let entries: VaultEntry[] = []
  export let working = false
  export let onClose: () => void
  export let onRename: (folder: Folder) => void
  export let onUnfile: (folder: Folder) => void

  const count = (folder: Folder) => entries.filter((entry) => entry.folderId === folder.id).length
</script>

<ModalShell onClose={() => !working && onClose()} labelledby="folder-manager-heading" describedby="folder-manager-description" modalClass="folder-manager-modal" ariaBusy={working}>
  <button type="button" class="modal-close" disabled={working} on:click={onClose} aria-label="Close folder organizer">×</button>
  <span class="confirm-icon"><Icon name="folder" size={20} /></span>
  <p class="eyebrow">Vault organization</p>
  <h2 id="folder-manager-heading">Organize folders</h2>
  <p id="folder-manager-description">Rename a folder everywhere or move its logins back to Unfiled.</p>
  {#if folders.length}
    <div class="folder-manager-list">
      {#each folders as folder (folder.id)}
        <article><span class="folder-manager-icon"><Icon name="folder" size={16} /></span><div><strong>{folder.name}</strong><small>{count(folder)} {count(folder) === 1 ? 'login' : 'logins'}</small></div><button type="button" disabled={working} on:click={() => onRename(folder)} aria-label={`Rename ${folder.name}`}><Icon name="pencil" size={15} /></button><button type="button" disabled={working} on:click={() => onUnfile(folder)} aria-label={`Move ${folder.name} logins to Unfiled`}><Icon name="folder-minus" size={15} /></button></article>
      {/each}
    </div>
  {:else}
    <div class="folder-manager-empty"><Icon name="folder" size={22} /><p>No folders yet.</p><span>Right-click a login or edit it to create one.</span></div>
  {/if}
  <div class="confirm-actions"><button type="button" class="primary-button" disabled={working} on:click={onClose}>Done</button></div>
</ModalShell>

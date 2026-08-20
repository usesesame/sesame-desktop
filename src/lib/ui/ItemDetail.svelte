<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import type { ItemDetail } from '../item-fields'
  import type { Folder, ItemKind } from '../types'
  import { itemKindIcon, itemKindLabel } from '../vault-items'

  const SECRET_REVEAL_TIMEOUT_MS = 30_000

  export let kind: ItemKind
  export let detail: ItemDetail
  export let folders: Folder[] = []
  export let onCopy: (value: string, label: string) => void
  export let onToggleFavourite: (favourite: boolean) => void
  export let onEdit: () => void
  export let onDelete: () => void
  export let onMove: (folderId?: string) => void
  export let onShowTag: (tag: string) => void

  let revealed: Record<string, boolean> = {}
  let revealTimers: Record<string, ReturnType<typeof setTimeout>> = {}

  function clearRevealTimers() {
    for (const timer of Object.values(revealTimers)) clearTimeout(timer)
    revealTimers = {}
    revealed = {}
  }

  function hide(label: string) {
    const { [label]: _hidden, ...rest } = revealed
    revealed = rest
    clearTimeout(revealTimers[label])
    const { [label]: _timer, ...timers } = revealTimers
    revealTimers = timers
  }

  function toggleReveal(label: string) {
    if (revealed[label]) {
      hide(label)
      return
    }
    revealed = { ...revealed, [label]: true }
    revealTimers = { ...revealTimers, [label]: setTimeout(() => hide(label), SECRET_REVEAL_TIMEOUT_MS) }
  }

  // A reveal must not survive the item it belongs to.
  $: if (detail) clearRevealTimers()
  onDestroy(clearRevealTimers)

  function attachmentSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
</script>

<div class="login-title-row">
  <div class="entry-avatar large-entry"><Icon name={itemKindIcon(kind)} size={20} /></div>
  <div>
    <h2>{detail.title}</h2>
    <div class="login-meta">
      <span>{itemKindLabel(kind)}</span>
      {#if detail.subtitle}<span class="item-subtitle">{detail.subtitle}</span>{/if}
    </div>
    {#if detail.tags.length}
      <div class="issue-chips">
        {#each detail.tags as tag (tag)}
          <button type="button" class="tag-chip" on:click={() => onShowTag(tag)}>{tag}</button>
        {/each}
      </div>
    {/if}
  </div>
  <div class="login-title-actions">
    <button type="button" class="card-favourite" class:active={detail.favourite} aria-label={detail.favourite ? 'Remove from favourites' : 'Add to favourites'} aria-pressed={detail.favourite} on:click={() => onToggleFavourite(!detail.favourite)}>{detail.favourite ? '★' : '☆'}</button>
    <button type="button" class="more-button" aria-label={`Edit ${detail.title}`} on:click={onEdit}><Icon name="more" size={19} /></button>
  </div>
</div>

{#if detail.fields.length}
  <section class="credentials-panel" aria-label={`${itemKindLabel(kind)} details`}>
    {#each detail.fields as field (field.label)}
      <div class="credential-row" class:credential-row-multiline={field.multiline}>
        <div class="credential-label"><Icon name={field.icon} size={16} /><span>{field.label}</span></div>
        {#if field.secret && !revealed[field.label]}
          <code class="concealed">••••••••••••••••</code>
        {:else}
          <code class:credential-block={field.multiline}>{field.value}</code>
        {/if}
        {#if field.secret}
          <button type="button" class="credential-button" aria-label={revealed[field.label] ? `Hide ${field.label}` : `Show ${field.label}`} aria-pressed={revealed[field.label]} on:click={() => toggleReveal(field.label)}><Icon name={revealed[field.label] ? 'eye-off' : 'eye'} size={16} /></button>
        {/if}
        <button type="button" class="credential-button" aria-label={`Copy ${field.label}`} on:click={() => onCopy(field.value, field.label)}><Icon name="copy" size={15} /></button>
      </div>
    {/each}
  </section>
{/if}

{#if detail.attachments.length}
  <section class="details-section">
    <div class="section-heading"><h3>Attachments</h3></div>
    <ul class="attachment-list">
      {#each detail.attachments as attachment (attachment.id)}
        <li><Icon name="file-key" size={15} /><span>{attachment.filename}</span><small>{attachmentSize(attachment.size)}</small></li>
      {/each}
    </ul>
  </section>
{/if}

{#if detail.notes}
  <section class="details-section">
    <div class="section-heading"><h3>Notes</h3></div>
    <p class="item-notes">{detail.notes}</p>
  </section>
{/if}

{#if detail.legacyFields.length}
  <section class="details-section">
    <div class="section-heading"><h3>Legacy data</h3></div>
    {#each detail.legacyFields as field, index (index)}
      <p><strong>{field.label}</strong>: {field.secret ? 'Secret value stored' : field.value} <button type="button" class="text-button" on:click={() => onCopy(field.value, field.label)}>Copy</button></p>
    {/each}
  </section>
{/if}

<section class="details-section">
  <div class="section-heading"><h3>Collection</h3></div>
  <div class="item-collection-row">
    <label class="sr-only" for="item-collection-select">Collection</label>
    <select id="item-collection-select" value={detail.folderId ?? ''} on:change={(event) => onMove(event.currentTarget.value || undefined)}>
      <option value="">Unfiled</option>
      {#each folders as folder (folder.id)}<option value={folder.id}>{folder.name}</option>{/each}
    </select>
    <button type="button" class="editor-delete" on:click={onDelete}>Delete</button>
  </div>
</section>

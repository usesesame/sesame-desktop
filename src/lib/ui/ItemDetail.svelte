<script lang="ts">
  import SecretText from './SecretText.svelte'
  import { noteText, vaultText } from '../vault-text'
  import Icon from '../Icon.svelte'
  import SelectMenu from './SelectMenu.svelte'
  import type { ItemDetail } from '../item-fields'
  import type { Folder, ItemKind } from '../types'
  import { itemKindIcon, itemKindLabel, uniqueTags } from '../vault-items'

  export let kind: ItemKind
  export let detail: ItemDetail
  export let folders: Folder[] = []
  export let revealed: Record<string, string> = {}
  export let onCopy: (value: string, label: string) => void
  export let onCopyField: (key: string, label: string) => void
  export let onReveal: (key: string) => void
  export let onHide: (key: string) => void
  export let onToggleFavourite: (favourite: boolean) => void
  export let onEdit: () => void
  export let onDelete: () => void
  export let onMove: (folderId?: string) => void
  export let onShowTag: (tag: string) => void
  export let onSetLock: (locked: boolean) => void = () => {}

  type DetailField = ItemDetail['fields'][number]

  function isShown(field: DetailField): boolean {
    return Boolean(field.secretKey) && revealed[field.secretKey as string] !== undefined
  }

  function shownValue(field: DetailField): string {
    return field.secretKey ? revealed[field.secretKey] ?? '' : field.value
  }

  function toggle(field: DetailField) {
    if (!field.secretKey) return
    if (isShown(field)) onHide(field.secretKey)
    else onReveal(field.secretKey)
  }

  function copyField(field: DetailField) {
    if (field.secretKey) onCopyField(field.secretKey, field.label)
    else onCopy(field.value, field.label)
  }

  function attachmentSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
</script>

<div class="login-title-row">
  <div class="entry-avatar large-entry"><Icon name={itemKindIcon(kind)} size={20} /></div>
  <div>
    <h2><bdi>{vaultText(detail.title)}</bdi></h2>
    <div class="login-meta">
      <span>{itemKindLabel(kind)}</span>
      {#if detail.subtitle}<span class="item-subtitle"><bdi>{vaultText(detail.subtitle)}</bdi></span>{/if}
    </div>
    {#if uniqueTags(detail.tags).length}
      <div class="issue-chips">
        {#each uniqueTags(detail.tags) as tag (tag)}
          <button type="button" class="tag-chip" on:click={() => onShowTag(tag)}><bdi>{vaultText(tag)}</bdi></button>
        {/each}
      </div>
    {/if}
  </div>
  <div class="login-title-actions">
    <button type="button" class="card-favourite" class:active={detail.favourite} aria-label={detail.favourite ? 'Remove from favourites' : 'Add to favourites'} aria-pressed={detail.favourite} on:click={() => onToggleFavourite(!detail.favourite)}>{detail.favourite ? '★' : '☆'}</button>
    <button type="button" class="more-button" aria-label={`Edit ${vaultText(detail.title)}`} title={`Edit ${vaultText(detail.title)}`} on:click={onEdit}><Icon name="more" size={19} /></button>
  </div>
</div>

{#if detail.fields.some((field) => !field.multiline)}
  <section class="credentials-panel" aria-label={`${itemKindLabel(kind)} details`}>
    {#each detail.fields as field, index (index)}
      {#if !field.multiline}
      <div class="credential-row">
        <div class="credential-label"><Icon name={field.icon} size={16} /><span><bdi>{vaultText(field.label)}</bdi></span></div>
        {#if field.secret && !isShown(field)}
          <code class="concealed">••••••••••••••••</code>
        {:else}
          <code>{#if field.secretKey}<SecretText value={shownValue(field)} />{:else}<bdi>{vaultText(shownValue(field))}</bdi>{/if}</code>
        {/if}
        {#if field.secret}
          <button type="button" class="credential-button" aria-label={isShown(field) ? `Hide ${vaultText(field.label)}` : `Show ${vaultText(field.label)}`} title={isShown(field) ? `Hide ${vaultText(field.label)}` : `Show ${vaultText(field.label)}`} aria-pressed={isShown(field)} on:click={() => toggle(field)}><Icon name={isShown(field) ? 'eye-off' : 'eye'} size={16} /></button>
        {/if}
        <button type="button" class="credential-button" aria-label={`Copy ${vaultText(field.label)}`} title={`Copy ${vaultText(field.label)}`} on:click={() => copyField(field)}><Icon name="copy" size={15} /></button>
      </div>
      {/if}
    {/each}
  </section>
{/if}
{#each detail.fields as field, index (index)}
  {#if field.multiline}
    <section class="details-section multiline-field" aria-label={vaultText(field.label)}>
      <div class="section-heading">
        <h3><bdi>{vaultText(field.label)}</bdi></h3>
        <div class="multiline-field-actions">
          {#if field.secret}
            <button type="button" class="credential-button" aria-label={isShown(field) ? `Hide ${vaultText(field.label)}` : `Show ${vaultText(field.label)}`} title={isShown(field) ? `Hide ${vaultText(field.label)}` : `Show ${vaultText(field.label)}`} aria-pressed={isShown(field)} on:click={() => toggle(field)}><Icon name={isShown(field) ? 'eye-off' : 'eye'} size={16} /></button>
          {/if}
          <button type="button" class="credential-button" aria-label={`Copy ${vaultText(field.label)}`} title={`Copy ${vaultText(field.label)}`} on:click={() => copyField(field)}><Icon name="copy" size={15} /></button>
        </div>
      </div>
      {#if field.secret && !isShown(field)}
        <p class="multiline-value concealed">••••••••••••••••</p>
      {:else}
        <p class="multiline-value" class:mono={kind !== 'secure_note'} dir="auto">{#if field.secretKey}<SecretText value={shownValue(field)} />{:else}{noteText(shownValue(field))}{/if}</p>
      {/if}
    </section>
  {/if}
{/each}

{#if detail.attachments.length}
  <section class="details-section">
    <div class="section-heading"><h3>Attachments</h3></div>
    <ul class="attachment-list">
      {#each detail.attachments as attachment (attachment.id)}
        <li><Icon name="file-key" size={15} /><span><bdi>{vaultText(attachment.filename)}</bdi></span><small>{attachmentSize(attachment.size)}</small></li>
      {/each}
    </ul>
  </section>
{/if}

{#if detail.notes}
  <section class="details-section">
    <div class="section-heading"><h3>Notes</h3></div>
    <p class="item-notes" dir="auto">{noteText(detail.notes)}</p>
  </section>
{/if}

{#if detail.legacyFields.length}
  <section class="details-section">
    <div class="section-heading"><h3>Legacy data</h3></div>
    {#each detail.legacyFields as field, index (index)}
      <p><strong><bdi>{vaultText(field.label)}</bdi></strong>: {#if field.secret}Secret value stored{:else}<bdi>{vaultText(field.value)}</bdi>{/if} <button type="button" class="text-button" on:click={() => (field.secret ? onCopyField(`legacy:${index}`, field.label) : onCopy(field.value, field.label))}>Copy</button></p>
    {/each}
  </section>
{/if}

{#if kind === 'secure_note'}
  <section class="details-section">
    <div class="section-heading"><h3>Protection</h3></div>
    <div class="item-collection-row">
      <p class="field-hint">{detail.locked ? 'Opening this note asks for your master password.' : 'This note shows whenever Sesame is unlocked.'}</p>
      <button type="button" class="secondary-button" on:click={() => onSetLock(!detail.locked)}>{detail.locked ? 'Remove the lock' : 'Lock with master password'}</button>
    </div>
  </section>
{/if}

<section class="details-section">
  <div class="section-heading"><h3>Collection</h3></div>
  <div class="item-collection-row">
    <SelectMenu
      id="item-collection-select"
      label="Collection"
      value={detail.folderId ?? ''}
      options={[{ value: '', label: 'Unfiled' }, ...folders.map((folder) => ({ value: folder.id, label: folder.name }))]}
      onChange={(next) => onMove(next || undefined)}
    />
    <button type="button" class="editor-delete" on:click={onDelete}>Delete</button>
  </div>
</section>

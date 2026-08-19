<script lang="ts">
  import { tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import { useAppStores } from '../stores/app-stores'
  import type { ImportSource } from '../types'
  import ModalShell from './ModalShell.svelte'

  export let importSources: Array<{ value: ImportSource; label: string }>
  export let onClose: () => void
  export let onChooseSource: (source: ImportSource) => void
  export let onHandleImport: () => void
  export let onResetImport: () => void
  export let onConfirmImport: () => void

  const { imports } = useAppStores()
  let sourceButton: HTMLButtonElement

  // Authenticator apps export codes, not items, so they have nothing to attach.
  const authenticatorSources: ImportSource[] = ['otpauth-txt', 'aegis-json', '2fas-json']
  $: importsWholeItems = !authenticatorSources.includes($imports.source)

  function sourceOptions() {
    const dialog = sourceButton?.closest<HTMLElement>('[role="dialog"]')
    return [...(dialog?.querySelectorAll<HTMLButtonElement>('#import-source-options [role="option"]') ?? [])]
  }

  async function openSourceMenu(focus: 'selected' | 'first' | 'last' = 'selected') {
    imports.patch({ sourceMenuOpen: true })
    await tick()
    const options = sourceOptions()
    const selected = options.find((option) => option.getAttribute('aria-selected') === 'true')
    const target = focus === 'first' ? options[0] : focus === 'last' ? options[options.length - 1] : selected ?? options[0]
    target?.focus()
  }

  function requestClose() {
    if ($imports.sourceMenuOpen) {
      imports.patch({ sourceMenuOpen: false })
      sourceButton?.focus()
      return
    }
    if (!$imports.importing) onClose()
  }

  function chooseSource(source: ImportSource) {
    imports.patch({ sourceMenuOpen: false })
    onChooseSource(source)
    sourceButton?.focus()
  }

  function handleSourceKeydown(event: KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      void openSourceMenu('selected')
    } else if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault()
      void openSourceMenu(event.key === 'Home' ? 'first' : 'last')
    }
  }

  function handleOptionKeydown(event: KeyboardEvent) {
    const options = sourceOptions()
    const current = Math.max(0, options.indexOf(event.currentTarget as HTMLButtonElement))
    let next: number | null = null
    if (event.key === 'ArrowDown') next = (current + 1) % options.length
    if (event.key === 'ArrowUp') next = (current - 1 + options.length) % options.length
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = options.length - 1
    if (next !== null) {
      event.preventDefault()
      options[next]?.focus()
      return
    }
    if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      imports.patch({ sourceMenuOpen: false })
      sourceButton?.focus()
      return
    }
    if (event.key === 'Tab') {
      imports.patch({ sourceMenuOpen: false })
      return
    }
    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const query = event.key.toLocaleLowerCase()
      const ordered = [...options.slice(current + 1), ...options.slice(0, current + 1)]
      const match = ordered.find((option) => option.textContent?.trim().toLocaleLowerCase().startsWith(query))
      if (match) {
        event.preventDefault()
        match.focus()
      }
    }
  }
</script>

<ModalShell open={true} onClose={requestClose} labelledby="import-heading" describedby="import-description" tone="" modalClass="import-modal" ariaBusy={$imports.importing}>
  <button type="button" class="modal-close" disabled={$imports.importing} on:click={requestClose} aria-label="Close import">×</button>
  <span class="import-icon"><Icon name="archive" size={21} /></span><p class="eyebrow">Import locally</p><h2 id="import-heading">{$imports.preview ? 'Check this import.' : 'Import your vault.'}</h2><p id="import-description">{$imports.preview ? `${$imports.fileName} stays on this device until you choose to add it.` : 'Reads it on this device before changing your vault.'}</p>
  <div class="import-source">
    <span id="import-source-label">Import from</span>
    <button bind:this={sourceButton} class="source-select" type="button" aria-haspopup="listbox" aria-labelledby="import-source-label" aria-controls="import-source-options" aria-expanded={$imports.sourceMenuOpen} on:click={() => imports.patch({ sourceMenuOpen: !$imports.sourceMenuOpen })} on:keydown={handleSourceKeydown} disabled={$imports.importing || Boolean($imports.preview)}>
      <span>{importSources.find((source) => source.value === $imports.source)?.label}</span>
      <svg viewBox="0 0 12 12" aria-hidden="true"><path d="m3 4.5 3 3 3-3" /></svg>
    </button>
    {#if $imports.sourceMenuOpen}
      <div id="import-source-options" class="source-menu" role="listbox" aria-labelledby="import-source-label">
        {#each importSources as source (source.value)}
          <button id={`import-source-${source.value}`} type="button" class:selected={source.value === $imports.source} role="option" aria-selected={source.value === $imports.source} tabindex="-1" on:click={() => chooseSource(source.value)} on:keydown={handleOptionKeydown}>{source.label}</button>
        {/each}
      </div>
    {/if}
  </div>
  {#if $imports.preview}
    <section class="import-preview" aria-live="polite">
      <div class="import-preview-head"><span><Icon name="shield" size={16} /></span><div><strong>{$imports.preview.totalEntries} {$imports.preview.totalEntries === 1 ? 'login' : 'logins'} found</strong><p>Review these details before anything is saved.</p></div></div>
      <dl>
        <div><dt>Exact duplicates already saved</dt><dd>{$imports.preview.exactDuplicates}</dd></div>
        <div><dt>Same account, different details</dt><dd>{$imports.preview.accountConflicts}</dd></div>
        <div><dt>Possible duplicates in this file</dt><dd>{$imports.preview.duplicateEntries}</dd></div>
        <div><dt>Website address missing</dt><dd>{$imports.preview.missingUrls}</dd></div>
        <div><dt>Website address unusable</dt><dd>{$imports.preview.invalidUrls}</dd></div>
        <div><dt>No 2FA secret found</dt><dd>{$imports.preview.noTotp}</dd></div>
        <div><dt>2FA secret unusable</dt><dd>{$imports.preview.invalidTotp}</dd></div>
        <div><dt>Fields kept as Legacy data</dt><dd>{$imports.preview.preservedLegacyFields}</dd></div>
        <div><dt>Secure notes found</dt><dd>{$imports.preview.secureNotes}</dd></div>
        <div><dt>Cards found</dt><dd>{$imports.preview.cards}</dd></div>
        <div><dt>Saved identities found</dt><dd>{$imports.preview.identities}</dd></div>
        <div><dt>SSH keys found</dt><dd>{$imports.preview.sshKeys}</dd></div>
        <div><dt>Passkeys Sesame cannot store yet</dt><dd>{$imports.preview.passkeysNotImported}</dd></div>
        <div><dt>Items Sesame cannot import yet</dt><dd>{$imports.preview.intentionallyOmittedItems}</dd></div>
      </dl>
      {#if $imports.preview.invalidTotp > 0 || $imports.preview.invalidUrls > 0}
        <div class="import-conflict-note"><Icon name="alert" size={16} /><p><strong>Some values could not be used.</strong><span>A 2FA secret that produces no code, or an address Sesame cannot open, is left out rather than saved. Everything else is imported.</span></p></div>
      {/if}
      {#if $imports.preview.accountConflicts > 0}
        <div class="import-conflict-note"><Icon name="copy" size={16} /><p><strong>Conflicting account details stay separate.</strong><span>Imported as separate logins for review. Existing logins are never overwritten.</span></p></div>
      {/if}
      {#if $imports.preview.preservedLegacyFields > 0}
        <div class="import-conflict-note"><Icon name="archive" size={16} /><p><strong>Extra imported fields are retained.</strong><span>Sesame keeps them in Legacy data on the related login. Review them after import.</span></p></div>
      {/if}
      {#if $imports.preview.passkeysNotImported > 0}
        <div class="import-conflict-note"><Icon name="key" size={16} /><p><strong>Passkeys are left in your old manager.</strong><span>Sesame has no passkey item yet, so {$imports.preview.passkeysNotImported === 1 ? 'one passkey stays' : `these ${$imports.preview.passkeysNotImported} passkeys stay`} where {$imports.preview.passkeysNotImported === 1 ? 'it is' : 'they are'}. Keep that manager until Sesame can store them.</span></p></div>
      {/if}
      {#if importsWholeItems}
        <div class="import-conflict-note"><Icon name="file-key" size={16} /><p><strong>File attachments are not in this export.</strong><span>This export format carries no attached files, so anything attached to an item stays only in your old manager. Save those files separately before you remove it.</span></p></div>
      {/if}
      {#if $imports.preview.intentionallyOmittedItems > 0}
        <div class="import-conflict-note"><Icon name="alert" size={16} /><p><strong>Some items are not imported.</strong><span>Sesame does not yet support this item type. Keep the original export until you have checked that the imported items are complete.</span></p></div>
      {/if}
      <label class="import-option"><input type="checkbox" checked={$imports.skipExactDuplicates} on:change={(event) => imports.patch({ skipExactDuplicates: event.currentTarget.checked })} /><span><strong>Skip exact duplicates</strong><small>Only logins with the same account details are skipped. Conflicts are still imported separately for review.</small></span></label>
      <div class="import-preview-actions"><button type="button" class="secondary-button" on:click={onResetImport} disabled={$imports.importing}>Choose another file</button><button type="button" class="primary-button" on:click={onConfirmImport} disabled={$imports.importing}>{$imports.importing ? 'Adding locally…' : 'Add to vault'}</button></div>
    </section>
  {:else}
    <button type="button" class="file-picker" class:busy={$imports.importing} on:click={onHandleImport} disabled={$imports.importing}><span>{$imports.importing ? 'Reading export…' : 'Choose export file'}</span><small>Sesame reads it on this device. Nothing is uploaded.</small></button>
  {/if}
  <p class="tiny-note">Exports are usually readable plaintext. After checking the import and making a Sesame backup, securely remove the export file if you no longer need it.</p>
</ModalShell>

<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'
  import type { CleanupEntry, DuplicateGroup, MergeChoices, MergeComparison } from '../types'

  export let mergeCandidate: { group: DuplicateGroup; entries: CleanupEntry[] } | null
  export let mergeKeepId = ''
  export let mergeComparison: MergeComparison | null = null
  export let mergeChoices: MergeChoices = {}
  export let cleanupWorking = false
  export let onCancel: () => void
  export let onConfirm: () => void

  let cancelButton: HTMLButtonElement
  let revealed: Record<string, boolean> = {}

  $: conflicts = (mergeComparison?.fields ?? []).filter((field) => field.differs)

  function cancel() {
    if (!cleanupWorking) onCancel()
  }

  function focusInitial(dialog: HTMLElement) {
    const selected = dialog.querySelector<HTMLInputElement>('input[name="keep-login"]:checked')
    ;(selected ?? cancelButton)?.focus()
  }

  function titleFor(entryId: string) {
    return mergeComparison?.entries.find((entry) => entry.id === entryId)?.title || 'This login'
  }

  function shown(field: { field: string; secret: boolean }, value: string) {
    if (!value) return 'Empty'
    if (field.secret && !revealed[field.field]) return '•'.repeat(Math.min(value.length, 12))
    return value
  }

  $: if (mergeKeepId) {
    for (const field of conflicts) {
      if (!mergeChoices[field.field]) mergeChoices = { ...mergeChoices, [field.field]: mergeKeepId }
    }
  }
</script>

{#if mergeCandidate}
  <ModalShell
    open={true}
    onClose={cancel}
    labelledby="merge-login-heading"
    describedby="merge-login-description"
    tone="cleanup-confirm"
    modalClass="cleanup-confirm-modal merge-confirm-modal"
    initialFocus={focusInitial}
    ariaBusy={cleanupWorking}
  >
    <span class="confirm-icon"><Icon name="copy" size={20} /></span>
    <h2 id="merge-login-heading">Choose the login to keep</h2>
    <p id="merge-login-description">Sesame keeps an encrypted copy of the vault first, so this can be undone.</p>
    <div class="keep-options" role="radiogroup" aria-label="Login to keep">
      {#each mergeCandidate.entries as entry (entry.id)}
        <label class:active={mergeKeepId === entry.id}><input type="radio" name="keep-login" value={entry.id} bind:group={mergeKeepId} /><span class="entry-avatar">{entry.initials || entry.title.slice(0, 1)}</span><span><strong>{entry.title}</strong><small>{entry.username || 'No username'} · {entry.site}</small></span></label>
      {/each}
    </div>

    {#if mergeKeepId && conflicts.length > 0}
      <div class="merge-fields">
        <p class="merge-fields-head"><strong>These fields differ.</strong> Choose which value survives.</p>
        {#each conflicts as field (field.field)}
          <fieldset class="merge-field">
            <legend>
              {field.label}
              {#if field.secret}
                <button type="button" class="text-button" on:click={() => (revealed = { ...revealed, [field.field]: !revealed[field.field] })}>{revealed[field.field] ? 'Hide' : 'Reveal'}</button>
              {/if}
            </legend>
            {#each field.options as option (option.entryId)}
              <label class:active={mergeChoices[field.field] === option.entryId}>
                <input type="radio" name={`merge-${field.field}`} value={option.entryId} checked={mergeChoices[field.field] === option.entryId} on:change={() => (mergeChoices = { ...mergeChoices, [field.field]: option.entryId })} />
                <span>
                  <small>{titleFor(option.entryId)}</small>
                  <code class:empty={!option.present}>{shown(field, option.value)}</code>
                </span>
              </label>
            {/each}
          </fieldset>
        {/each}
      </div>
    {:else if mergeKeepId && mergeComparison}
      <p class="merge-fields-head">These logins agree on every field. Nothing will be lost.</p>
    {/if}

    <div class="confirm-actions"><button bind:this={cancelButton} type="button" class="secondary-button" disabled={cleanupWorking} on:click={cancel}>Cancel</button><button type="button" class="primary-button" disabled={!mergeKeepId || cleanupWorking} on:click={onConfirm}>{cleanupWorking ? 'Merging…' : `Merge ${mergeCandidate.entries.length} logins`}</button></div>
  </ModalShell>
{/if}

<script lang="ts">
  import { onDestroy } from 'svelte'
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'
  import { messageFor } from '../controllers/feedback-controller'
  import type { CleanupEntry, DuplicateGroup, MergeChoices, MergeComparison, MergeField, MergeFieldOption } from '../types'
  import { grantPresence, PRESENCE_REQUIRED, revealLoginSecret } from '../vault'

  const REVEAL_TIMEOUT_MS = 30_000

  export let mergeCandidate: { group: DuplicateGroup; entries: CleanupEntry[] } | null
  export let mergeKeepId = ''
  export let mergeComparison: MergeComparison | null = null
  export let mergeChoices: MergeChoices = {}
  export let cleanupWorking = false
  export let onCancel: () => void
  export let onConfirm: () => void

  let cancelButton: HTMLButtonElement
  let revealed: { entryId: string; value: string } | null = null
  let revealTimer: ReturnType<typeof setTimeout> | undefined
  let revealGeneration = 0
  let revealWorking = false
  let revealError = ''
  let presenceFor = ''
  let presenceSecret = ''
  let presenceError = ''

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

  function hideRevealed() {
    revealGeneration += 1
    clearTimeout(revealTimer)
    revealed = null
  }

  function closePresence() {
    presenceFor = ''
    presenceSecret = ''
    presenceError = ''
  }

  async function readPassword(entryId: string) {
    const generation = revealGeneration
    revealWorking = true
    try {
      const value = await revealLoginSecret(entryId)
      if (generation !== revealGeneration) return
      revealed = { entryId, value }
      revealTimer = setTimeout(hideRevealed, REVEAL_TIMEOUT_MS)
      closePresence()
      revealError = ''
    } catch (error) {
      if (generation !== revealGeneration) return
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) {
        presenceFor = entryId
        presenceError = ''
      } else if (presenceFor) {
        presenceError = messageFor(error)
      } else {
        revealError = messageFor(error)
      }
    } finally {
      revealWorking = false
    }
  }

  async function togglePassword(entryId: string) {
    if (revealWorking) return
    const wasShown = revealed?.entryId === entryId
    hideRevealed()
    closePresence()
    revealError = ''
    if (!wasShown) await readPassword(entryId)
  }

  async function confirmPresence() {
    if (!presenceSecret || revealWorking) return
    const entryId = presenceFor
    revealWorking = true
    try {
      await grantPresence(presenceSecret)
    } catch (error) {
      presenceError = messageFor(error)
      presenceSecret = ''
      revealWorking = false
      return
    }
    presenceSecret = ''
    revealWorking = false
    if (!destroyed) await readPassword(entryId)
  }

  function canShow(field: MergeField, option: MergeFieldOption) {
    return field.field === 'password' && option.present
  }

  function shown(field: MergeField, option: MergeFieldOption, current: typeof revealed) {
    if (!option.present) return 'Empty'
    if (!field.secret) return option.value ?? ''
    if (current?.entryId === option.entryId && field.field === 'password') return current.value
    return 'Hidden'
  }

  let destroyed = false

  onDestroy(() => {
    destroyed = true
    hideRevealed()
    presenceSecret = ''
  })

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
        <p class="merge-fields-head"><strong>These fields differ.</strong> Choose which value survives. Passwords, 2FA secrets, notes and backup codes stay hidden, and you can show one password at a time.</p>
        {#each conflicts as field (field.field)}
          <fieldset class="merge-field">
            <legend>{field.label}</legend>
            {#each field.options as option (option.entryId)}
              <div class="merge-option">
                <label class:active={mergeChoices[field.field] === option.entryId}>
                  <input type="radio" name={`merge-${field.field}`} value={option.entryId} checked={mergeChoices[field.field] === option.entryId} on:change={() => (mergeChoices = { ...mergeChoices, [field.field]: option.entryId })} />
                  <span>
                    <small>{titleFor(option.entryId)}</small>
                    <code class:empty={!option.present || (field.secret && revealed?.entryId !== option.entryId)}>{shown(field, option, revealed)}</code>
                  </span>
                </label>
                {#if canShow(field, option)}
                  <button type="button" class="text-button" disabled={revealWorking} aria-label={`${revealed?.entryId === option.entryId ? 'Hide' : 'Show'} the password of ${titleFor(option.entryId)}`} on:click={() => togglePassword(option.entryId)}>{revealed?.entryId === option.entryId ? 'Hide' : 'Show'}</button>
                {/if}
              </div>
            {/each}
          </fieldset>
        {/each}
        {#if revealError}<p class="form-error" role="alert">{revealError}</p>{/if}
        {#if presenceFor}
          <form class="presence-confirm" novalidate on:submit|preventDefault={confirmPresence}>
            <label class="delete-vault-input" for="merge-presence-password">Master password</label>
            <input
              id="merge-presence-password"
              name="merge-presence-password"
              type="password"
              bind:value={presenceSecret}
              autocomplete="current-password"
              spellcheck="false"
              disabled={revealWorking}
              aria-invalid={Boolean(presenceError)}
              aria-describedby={presenceError ? 'merge-presence-error' : undefined}
            />
            {#if presenceError}<p id="merge-presence-error" class="form-error" role="alert">{presenceError}</p>{/if}
            <div class="confirm-actions">
              <button type="button" class="secondary-button" disabled={revealWorking} on:click={closePresence}>Cancel</button>
              <button type="submit" class="secondary-button" disabled={!presenceSecret || revealWorking}>{revealWorking ? 'Confirming…' : 'Confirm and show'}</button>
            </div>
          </form>
        {/if}
      </div>
    {:else if mergeKeepId && mergeComparison}
      <p class="merge-fields-head">These logins agree on every field. Nothing will be lost.</p>
    {/if}

    <div class="confirm-actions"><button bind:this={cancelButton} type="button" class="secondary-button" disabled={cleanupWorking} on:click={cancel}>Cancel</button><button type="button" class="primary-button" disabled={!mergeKeepId || cleanupWorking} on:click={onConfirm}>{cleanupWorking ? 'Merging…' : `Merge ${mergeCandidate.entries.length} logins`}</button></div>
  </ModalShell>
{/if}

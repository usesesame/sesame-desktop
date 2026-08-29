<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import Icon from '../Icon.svelte'
  import type { SshKeyInput } from '../types'

  export let keyDraft: SshKeyInput
  export let editorTitle = 'Add a key'
  export let savingKey = false
  export let loadingKey = false
  export let onSubmit: () => void
  export let onClose: () => void

  let titleInput: HTMLInputElement

  // Tracked from input events, not a snapshot, so nothing holds a second copy of the record.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingKey) return
    if (dirty) {
      confirmingDiscard = true
      return
    }
    onClose()
  }

  function discard() {
    confirmingDiscard = false
    dirty = false
    onClose()
  }

  function focusInitial() {
    titleInput?.focus()
  }

  let passphraseVisible = false

  // A public key names its own algorithm in the first field, so nobody should
  // have to retype it. Private keys do not, except for the older PEM headers.
  const keyTypes: Array<{ prefix: string; name: string }> = [
    { prefix: 'sk-ssh-ed25519@openssh.com', name: 'ed25519-sk' },
    { prefix: 'sk-ecdsa-sha2-nistp256@openssh.com', name: 'ecdsa-sk' },
    { prefix: 'ssh-ed25519', name: 'ed25519' },
    { prefix: 'ecdsa-sha2-', name: 'ecdsa' },
    { prefix: 'ssh-rsa', name: 'rsa' },
    { prefix: 'ssh-dss', name: 'dsa' },
  ]

  function keyTypeOf(publicKey: string, privateKey: string): string {
    const first = publicKey.trim().split(/\s+/)[0] ?? ''
    const match = keyTypes.find((entry) => first.startsWith(entry.prefix))
    if (match) return match.name
    if (/BEGIN RSA PRIVATE KEY/.test(privateKey)) return 'rsa'
    if (/BEGIN EC PRIVATE KEY/.test(privateKey)) return 'ecdsa'
    if (/BEGIN DSA PRIVATE KEY/.test(privateKey)) return 'dsa'
    return ''
  }

  // Fills a blank only, so a type set by hand survives a later paste.
  function fillKeyType() {
    if (keyDraft.keyType.trim()) return
    const detected = keyTypeOf(keyDraft.publicKey, keyDraft.privateKey)
    if (detected) keyDraft = { ...keyDraft, keyType: detected }
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="ssh-key-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingKey || loadingKey}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{keyDraft.id ? 'Saved key' : 'New key'}</p><h2 id="ssh-key-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingKey} on:click={requestClose} aria-label="Close key editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Name <span class="field-hint">How this key appears in your list, e.g. “Deploy key”</span><input name="ssh-key-title" bind:this={titleInput} bind:value={keyDraft.title} required maxlength="160" placeholder="e.g. Deploy key…" autocomplete="off" /></label>
    <label>Key type <span class="field-hint">Read from the key you paste</span><input name="ssh-key-type" bind:value={keyDraft.keyType} maxlength="32" autocomplete="off" placeholder="e.g. ed25519…" spellcheck="false" /></label>
    <label>Private key<textarea name="ssh-private-key" bind:value={keyDraft.privateKey} on:input={fillKeyType} rows="6" maxlength="16000" class="monospace-field" spellcheck="false"></textarea></label>
    <label>Public key<textarea name="ssh-public-key" bind:value={keyDraft.publicKey} on:input={fillKeyType} rows="3" maxlength="4000" class="monospace-field" spellcheck="false"></textarea></label>
    <label>Passphrase
      <span class="password-field single">
        <input name="ssh-passphrase" bind:value={keyDraft.passphrase} maxlength="256" autocomplete="off" spellcheck="false" type={passphraseVisible ? 'text' : 'password'} />
        <button type="button" class="icon-button" aria-label={passphraseVisible ? 'Hide passphrase' : 'Show passphrase'} aria-pressed={passphraseVisible} on:click={() => (passphraseVisible = !passphraseVisible)}><Icon name={passphraseVisible ? 'eye-off' : 'eye'} size={15} /></button>
      </span>
    </label>
    <label>Notes<textarea name="ssh-key-notes" bind:value={keyDraft.notes} rows="4" maxlength="4000"></textarea></label>
    <label>Tags <span class="field-hint">Comma separated, optional</span><input name="ssh-key-tags" value={keyDraft.tags.join(', ')} on:input={(event) => (keyDraft = { ...keyDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="500" autocomplete="off" placeholder="e.g. work, deploy…" /></label>
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This key has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer"><div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingKey} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingKey || loadingKey}>{savingKey ? 'Saving…' : 'Save key'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

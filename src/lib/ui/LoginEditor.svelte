<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import Icon from '../Icon.svelte'
  import { generatorLabels, generatorOptionKeys } from '../generator'
  import { useAppStores } from '../stores/app-stores'
  import { suggestFieldValues } from '../vault'
  import type { Folder, LoginInput } from '../types'

  // Fetched once per field on first focus; no store, so nothing survives a lock.
  let usernameSuggestions: string[] = []
  let emailSuggestions: string[] = []

  async function loadSuggestions(field: 'username' | 'email') {
    const target = field === 'username' ? usernameSuggestions : emailSuggestions
    if (target.length) return
    try {
      const values = await suggestFieldValues(field)
      if (field === 'username') usernameSuggestions = values
      else emailSuggestions = values
    } catch {
      // Losing a suggestion list costs nothing; fail silently.
    }
  }

  const { generator } = useAppStores()

  export let loginDraft: LoginInput
  export let folderOptions: Folder[] = []
  export let editorTitle = 'Add a login'
  export let savingLogin = false
  export let focusUrl = false
  export let onSubmit: () => void
  export let onClose: () => void
  export let onDelete: () => void

  let nameInput: HTMLInputElement
  let urlInput: HTMLInputElement

  // Tracked from input events, not a draft snapshot, which would hold a second copy of the password.
  let dirty = false
  let confirmingDiscard = false

  function requestClose() {
    if (savingLogin) return
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

  let generatorOpen = false

  /// Copies the generated password in; nothing touches the clipboard.
  function takeGenerated() {
    if (!$generator.password) return
    loginDraft = { ...loginDraft, password: $generator.password }
    dirty = true
  }

  function generatePassword() {
    generator.generate()
    takeGenerated()
  }

  function adjust(change: () => void) {
    const hadPassword = Boolean($generator.password)
    change()
    if (hadPassword) takeGenerated()
  }

  // Starts hidden every time the editor opens, since the component is rebuilt.
  let passwordVisible = false

  function focusInitial() {
    if (focusUrl && urlInput) {
      urlInput.focus()
      urlInput.select()
    } else {
      nameInput?.focus()
    }
  }

  function setFolder(event: Event) {
    const folderId = (event.currentTarget as HTMLSelectElement).value
    const folder = folderOptions.find((candidate) => candidate.id === folderId)
    loginDraft = { ...loginDraft, folderId: folder?.id, folder: folder?.name ?? '' }
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="login-editor-heading"
  tone="editor"
  modalClass="login-editor"
  initialFocus={focusInitial}
  ariaBusy={savingLogin}
>
  <form on:submit|preventDefault={onSubmit} on:input={() => (dirty = true)} on:change={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{loginDraft.id ? 'Saved login' : 'New login'}</p><h2 id="login-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingLogin} on:click={requestClose} aria-label="Close login editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Login name<input bind:this={nameInput} bind:value={loginDraft.title} required maxlength="160" placeholder="e.g. GitHub" autocomplete="off" /></label>
    <label>Website <span class="field-hint">Used for opening and browser filling; "www" is treated as the same site</span><input bind:this={urlInput} bind:value={loginDraft.url} maxlength="2048" placeholder="e.g. github.com" inputmode="url" autocomplete="url" /></label>
    <label>Additional websites <span class="field-hint">One http or https address per line. Sesame does not fill across origins.</span><textarea value={(loginDraft.urls ?? []).join('\n')} on:input={(event) => (loginDraft = { ...loginDraft, urls: event.currentTarget.value.split('\n').map((value) => value.trim()).filter(Boolean) })} placeholder="https://github.com/login"></textarea></label>
    <label>Tags <span class="field-hint">Optional. Separate tags with commas.</span><input value={(loginDraft.tags ?? []).join(', ')} on:input={(event) => (loginDraft = { ...loginDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="10000" autocomplete="off" /></label>
    <label>Folder <span class="field-hint">Optional. Create and rename folders from the vault organizer.</span><select value={loginDraft.folderId ?? ''} on:change={setFolder}><option value="">Unfiled</option>{#each folderOptions as folder (folder.id)}<option value={folder.id}>{folder.name}</option>{/each}</select></label>
    <div class="editor-two-column">
      <label>Username <span class="field-hint">What the site calls a sign-in name, if it is not your email</span><input bind:value={loginDraft.username} maxlength="2048" autocomplete="username" list="username-suggestions" on:focus={() => loadSuggestions('username')} /></label>
      <label>Email <span class="field-hint">Only if the site asks for this separately from a username</span><input bind:value={loginDraft.email} maxlength="2048" inputmode="email" autocomplete="email" list="email-suggestions" on:focus={() => loadSuggestions('email')} /></label>
      <datalist id="username-suggestions">{#each usernameSuggestions as value (value)}<option {value}></option>{/each}</datalist>
      <datalist id="email-suggestions">{#each emailSuggestions as value (value)}<option {value}></option>{/each}</datalist>
    </div>
    <label>Password
      <span class="password-field">
        <input bind:value={loginDraft.password} maxlength="8192" type={passwordVisible ? 'text' : 'password'} autocomplete="new-password" spellcheck="false" />
        <button type="button" class="icon-button" aria-label={passwordVisible ? 'Hide password' : 'Show password'} title={passwordVisible ? 'Hide password' : 'Show password'} aria-pressed={passwordVisible} on:click={() => (passwordVisible = !passwordVisible)}><Icon name={passwordVisible ? 'eye-off' : 'eye'} size={15} /></button>
        <button type="button" class="icon-button" aria-label="Generate a password" title="Generate a password" on:click={generatePassword}><Icon name="refresh" size={15} /></button>
        <button type="button" class="icon-button" aria-label="Password options" title="Password options" aria-expanded={generatorOpen} on:click={() => (generatorOpen = !generatorOpen)}><Icon name="settings" size={15} /></button>
      </span>
    </label>

    {#if generatorOpen}
      <section class="editor-generator" aria-label="Password options">
        <div class="editor-generator-top">
          <span class="strength-label" class:very-strong={$generator.strength === 'Very strong'}>{$generator.password ? $generator.strength : 'Not generated yet'}</span>
          <span>{$generator.length} characters, about {$generator.entropy} bits</span>
        </div>
        <div class="strength-track" aria-hidden="true"><span class:weak={$generator.strength === 'Weak'} class:fair={$generator.strength === 'Fair'} style={`width: ${$generator.password ? $generator.strengthPercent : 0}%`}></span></div>
        <div class="length-setting">
          <strong>Length</strong>
          <div class="length-stepper">
            <button type="button" aria-label="Shorten password" disabled={$generator.length <= 12} on:click={() => adjust(() => generator.changeLength(-1))}>&minus;</button>
            <output>{$generator.length}</output>
            <button type="button" aria-label="Lengthen password" disabled={$generator.length >= 64} on:click={() => adjust(() => generator.changeLength(1))}>+</button>
          </div>
        </div>
        <div class="generator-toggles">{#each generatorOptionKeys as option (option)}<button type="button" class:active={$generator.options[option]} aria-pressed={$generator.options[option]} on:click={() => adjust(() => generator.toggleOption(option))}><span class="toggle-check">{#if $generator.options[option]}<Icon name="check" size={12} />{/if}</span>{generatorLabels[option]}</button>{/each}</div>
        <button type="button" class="ambiguity-toggle" class:active={$generator.avoidAmbiguous} aria-pressed={$generator.avoidAmbiguous} on:click={() => adjust(generator.toggleAmbiguous)}><span class="toggle-switch"><span></span></span><span><strong>Avoid similar characters</strong><small>Removes I, l, 1, O, 0, and o.</small></span></button>
      </section>
    {/if}

    <section class="editor-section">
      <div><h3>Two-factor code</h3><p>Paste the base32 secret or the full <code>otpauth://</code> link.</p></div>
      <label class="field-only-label">2FA secret<input bind:value={loginDraft.totp} placeholder="Optional" autocomplete="off" /></label>
    </section>

    <section class="editor-section">
      <div><h3>Account recovery</h3><p>Keep only the options this site actually offers.</p></div>
      <label class="recovery-applicability"><input type="checkbox" bind:checked={loginDraft.recoveryNotApplicable} /><span><strong>This site has no separate recovery options</strong><small>Use this when there are no backup codes, recovery email, or recovery phone.</small></span></label>
      {#if !loginDraft.recoveryNotApplicable}
        <label>Backup codes<textarea value={loginDraft.backupCodes.join('\n')} on:input={(event) => (loginDraft = { ...loginDraft, backupCodes: event.currentTarget.value.split(/[\n,]/).map((value) => value.trim()).filter(Boolean) })} placeholder="One code per line"></textarea></label>
        <div class="editor-two-column">
          <label>Recovery email <span class="field-hint">Optional</span><input bind:value={loginDraft.recoveryEmail} inputmode="email" autocomplete="email" /></label>
          <label>Recovery phone <span class="field-hint">Optional</span><input bind:value={loginDraft.recoveryPhone} inputmode="tel" autocomplete="tel" /></label>
        </div>
      {/if}
    </section>

    <label>Notes<textarea bind:value={loginDraft.notes} maxlength="20000" placeholder="Anything useful to remember about this account"></textarea></label>
  </div>

  {#if confirmingDiscard}
    <footer class="editor-footer discard-confirm">
      <p><strong>Discard your changes?</strong> This login has edits that have not been saved.</p>
      <div class="editor-footer-actions">
        <button type="button" class="secondary-button" on:click={() => (confirmingDiscard = false)}>Keep editing</button>
        <button type="button" class="editor-delete" on:click={discard}>Discard changes</button>
      </div>
    </footer>
  {:else}
    <footer class="editor-footer">{#if loginDraft.id}<button type="button" class="editor-delete" disabled={savingLogin} on:click={onDelete}>Delete login</button>{/if}<div class="editor-footer-actions"><button type="button" class="secondary-button" disabled={savingLogin} on:click={requestClose}>Cancel</button><button class="primary-button" type="submit" disabled={savingLogin}>{savingLogin ? 'Saving…' : 'Save login'}</button></div></footer>
  {/if}
  </form>
</ModalShell>

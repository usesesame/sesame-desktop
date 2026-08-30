<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import SelectMenu from './SelectMenu.svelte'
  import Icon from '../Icon.svelte'
  import { generatorLabels, generatorOptionKeys } from '../generator'
  import { useAppStores } from '../stores/app-stores'
  import { grantPresence, PRESENCE_REQUIRED, revealLoginSecret, suggestFieldValues } from '../vault'
  import { messageFor } from '../controllers/feedback-controller'
  import PasswordPresenceModal from './PasswordPresenceModal.svelte'
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
  export let hasTotp = false
  export let onSubmit: (totpEntered: boolean) => void
  export let onClose: () => void
  export let onDelete: () => void

  let nameInput: HTMLInputElement
  let urlInput: HTMLInputElement

  // Tracked from input events, not a draft snapshot, which would hold a second copy of the password.
  let dirty = false
  let confirmingDiscard = false
  let totpEntered = false

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
    passwordDisplay = $generator.password
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

  // The saved secret stays out of the draft until someone asks to see it, so a
  // save with an untouched field still means "keep the stored password".
  let passwordDisplay = ''
  let passwordRevealWorking = false
  let revealError = ''
  let presenceOpen = false
  let presenceSecret = ''
  let presenceError = ''

  async function togglePasswordVisibility() {
    if (passwordDisplay) {
      passwordVisible = !passwordVisible
      return
    }
    if (!loginDraft.id || passwordRevealWorking) return
    passwordRevealWorking = true
    revealError = ''
    try {
      passwordDisplay = await revealLoginSecret(loginDraft.id)
      passwordVisible = true
    } catch (error) {
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) presenceOpen = true
      else revealError = messageFor(error)
    } finally {
      passwordRevealWorking = false
    }
  }

  async function confirmEditorPresence() {
    if (!loginDraft.id) return
    try {
      await grantPresence(presenceSecret)
    } catch (error) {
      presenceError = messageFor(error)
      presenceSecret = ''
      return
    }
    try {
      passwordDisplay = await revealLoginSecret(loginDraft.id)
      passwordVisible = true
      presenceOpen = false
      presenceSecret = ''
      presenceError = ''
    } catch (error) {
      presenceError = messageFor(error)
    }
  }

  function cancelEditorPresence() {
    presenceOpen = false
    presenceSecret = ''
    presenceError = ''
  }

  function focusInitial() {
    if (focusUrl && urlInput) {
      urlInput.focus()
      urlInput.select()
    } else {
      nameInput?.focus()
    }
  }

  function setFolder(folderId: string) {
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
  <form on:submit|preventDefault={() => onSubmit(totpEntered)} on:input={() => (dirty = true)} on:change={() => (dirty = true)}>
  <header class="editor-header">
    <div><p class="eyebrow">{loginDraft.id ? 'Saved login' : 'New login'}</p><h2 id="login-editor-heading">{editorTitle}</h2></div>
    <button class="modal-close" type="button" disabled={savingLogin} on:click={requestClose} aria-label="Close login editor">×</button>
  </header>

  <div class="editor-fields">
    <label>Login name<input name="login-title" bind:this={nameInput} bind:value={loginDraft.title} required maxlength="160" placeholder="e.g. GitHub…" autocomplete="off" /></label>
    <label>Website <span class="field-hint">Used for opening and browser filling; "www" is treated as the same site</span><input name="login-url" bind:this={urlInput} bind:value={loginDraft.url} maxlength="2048" placeholder="e.g. github.com…" inputmode="url" autocomplete="url" spellcheck="false" /></label>
    <label>Additional websites <span class="field-hint">One http or https address per line. Sesame does not fill across origins.</span><textarea name="login-urls" value={(loginDraft.urls ?? []).join('\n')} on:input={(event) => (loginDraft = { ...loginDraft, urls: event.currentTarget.value.split('\n').map((value) => value.trim()).filter(Boolean) })} placeholder="https://github.com/login" spellcheck="false"></textarea></label>
    <label>Tags <span class="field-hint">Optional. Separate tags with commas.</span><input name="login-tags" value={(loginDraft.tags ?? []).join(', ')} on:input={(event) => (loginDraft = { ...loginDraft, tags: event.currentTarget.value.split(',').map((value) => value.trim()).filter(Boolean) })} maxlength="10000" autocomplete="off" /></label>
    <label>Folder <span class="field-hint">Optional. Create and rename folders from the vault organizer.</span>
      <SelectMenu
        label="Folder"
        value={loginDraft.folderId ?? ''}
        options={[{ value: '', label: 'Unfiled' }, ...folderOptions.map((folder) => ({ value: folder.id, label: folder.name }))]}
        onChange={setFolder}
      />
    </label>
    <div class="editor-two-column">
      <label>Username <span class="field-hint">What the site calls a sign-in name, if it is not your email</span><input name="login-username" bind:value={loginDraft.username} maxlength="2048" autocomplete="username" spellcheck="false" list="username-suggestions" on:focus={() => loadSuggestions('username')} /></label>
      <label>Email <span class="field-hint">Only if the site asks for this separately from a username</span><input name="login-email" type="email" bind:value={loginDraft.email} maxlength="2048" autocomplete="email" spellcheck="false" list="email-suggestions" on:focus={() => loadSuggestions('email')} /></label>
      <datalist id="username-suggestions">{#each usernameSuggestions as value (value)}<option {value}></option>{/each}</datalist>
      <datalist id="email-suggestions">{#each emailSuggestions as value (value)}<option {value}></option>{/each}</datalist>
    </div>
    <label>Password
      <span class="password-field">
        <input name="login-password" value={passwordDisplay} maxlength="8192" type={passwordVisible ? 'text' : 'password'} autocomplete="new-password" spellcheck="false" placeholder={loginDraft.id ? 'Leave blank to keep the saved password' : ''} on:input={(event) => { passwordDisplay = event.currentTarget.value; loginDraft = { ...loginDraft, password: passwordDisplay } }} />
        <button type="button" class="icon-button" aria-label={passwordVisible ? 'Hide password' : 'Show password'} title={passwordVisible ? 'Hide password' : 'Show password'} aria-pressed={passwordVisible} disabled={(!passwordDisplay && !loginDraft.id) || passwordRevealWorking} on:click={togglePasswordVisibility}><Icon name={passwordVisible ? 'eye-off' : 'eye'} size={15} /></button>
        <button type="button" class="icon-button" aria-label="Generate a password" title="Generate a password" on:click={generatePassword}><Icon name="refresh" size={15} /></button>
        <button type="button" class="icon-button" aria-label="Password options" title="Password options" aria-expanded={generatorOpen} on:click={() => (generatorOpen = !generatorOpen)}><Icon name="settings" size={15} /></button>
      </span>
    </label>
    {#if revealError}<p class="form-error" role="alert">{revealError}</p>{/if}

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
      <label class="field-only-label">2FA secret<input name="login-totp" bind:value={loginDraft.totp} on:input={() => (totpEntered = true)} placeholder={hasTotp ? 'Configured. Type a new secret to replace it, or clear the field to remove 2FA.' : 'Optional'} autocomplete="off" spellcheck="false" /></label>
    </section>

    <section class="editor-section">
      <div><h3>Account recovery</h3><p>Keep only the options this site actually offers.</p></div>
      <label class="recovery-applicability"><input name="login-recovery-not-applicable" type="checkbox" bind:checked={loginDraft.recoveryNotApplicable} /><span><strong>This site has no separate recovery options</strong><small>Use this when there are no backup codes, recovery email, or recovery phone.</small></span></label>
      {#if !loginDraft.recoveryNotApplicable}
        <label>Backup codes<textarea name="login-backup-codes" value={loginDraft.backupCodes.join('\n')} on:input={(event) => (loginDraft = { ...loginDraft, backupCodes: event.currentTarget.value.split(/[\n,]/).map((value) => value.trim()).filter(Boolean) })} placeholder="One code per line…" spellcheck="false"></textarea></label>
        <div class="editor-two-column">
          <label>Recovery email <span class="field-hint">Optional</span><input name="login-recovery-email" type="email" bind:value={loginDraft.recoveryEmail} autocomplete="email" spellcheck="false" /></label>
          <label>Recovery phone <span class="field-hint">Optional</span><input name="login-recovery-phone" type="tel" bind:value={loginDraft.recoveryPhone} autocomplete="tel" /></label>
        </div>
      {/if}
    </section>

    <label>Notes<textarea name="login-notes" bind:value={loginDraft.notes} maxlength="20000" placeholder="Anything useful to remember about this account…"></textarea></label>
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

  {#if presenceOpen}
    <PasswordPresenceModal bind:presenceSecret={presenceSecret} errorMessage={presenceError} onConfirm={confirmEditorPresence} onCancel={cancelEditorPresence} />
  {/if}
</ModalShell>

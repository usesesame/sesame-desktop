<script lang="ts">
  import { onMount, tick } from 'svelte'
  import { emailAliases, loadEmailAliases, removeEmailAliases, saveEmailAliases, serviceNames } from '../email-aliases'
  import { messageFor } from '../controllers/feedback-controller'
  import SelectMenu from './SelectMenu.svelte'
  import type { EmailAliasService } from '../types'

  const DEFAULT_ADDY_DOMAIN = 'anonaddy.me'
  const serviceOptions: { value: EmailAliasService; label: string }[] = [
    { value: 'addy', label: serviceNames.addy },
    { value: 'simpleLogin', label: serviceNames.simpleLogin },
  ]
  const DOMAIN_ERROR = 'Enter the domain your aliases use'
  const TOKEN_ERRORS = ['Paste the API token', 'That does not look like an API token']
  const tokenHelp: Record<EmailAliasService, string> = {
    addy: 'Create an API key in your addy.io account under Settings, then API Keys.',
    simpleLogin: 'Create an API key in your SimpleLogin account under API Keys.',
  }

  let formOpen = false
  let service: EmailAliasService = 'addy'
  let token = ''
  let domain = DEFAULT_ADDY_DOMAIN
  let working = false
  let errorMessage = ''
  let tokenInput: HTMLInputElement | undefined
  let switchButton: HTMLButtonElement | undefined
  let replaceButton: HTMLButtonElement | undefined
  let openedFrom: 'switch' | 'replace' = 'switch'
  let loadFailed = false

  $: status = $emailAliases
  $: known = status !== null
  $: enabled = Boolean(status?.service)
  $: errorField = errorMessage.startsWith(DOMAIN_ERROR) ? 'domain' : TOKEN_ERRORS.some((start) => errorMessage.startsWith(start)) ? 'token' : null

  onMount(load)

  function load() {
    loadFailed = false
    errorMessage = ''
    loadEmailAliases().catch((error) => {
      errorMessage = messageFor(error)
      loadFailed = true
    })
  }

  function openForm(from: 'switch' | 'replace') {
    openedFrom = from
    service = status?.service ?? 'addy'
    domain = status?.domain ?? DEFAULT_ADDY_DOMAIN
    token = ''
    errorMessage = ''
    formOpen = true
    void tick().then(() => tokenInput?.focus())
  }

  function closeForm() {
    formOpen = false
    token = ''
    errorMessage = ''
    void tick().then(() => (openedFrom === 'replace' && replaceButton ? replaceButton : switchButton)?.focus())
  }

  async function run(action: () => Promise<unknown>): Promise<boolean> {
    if (working) return false
    working = true
    errorMessage = ''
    try {
      await action()
      return true
    } catch (error) {
      errorMessage = messageFor(error)
      return false
    } finally {
      working = false
    }
  }

  async function save() {
    const typed = token
    token = ''
    const saved = await run(() => saveEmailAliases({ service, token: typed, domain: service === 'addy' ? domain : undefined, nameSite: Boolean(status && status.service === service && status.nameSite) }))
    if (saved) closeForm()
  }

  function toggle() {
    if (!known) return
    if (enabled) {
      void run(removeEmailAliases).then((removed) => { if (removed) closeForm() })
    } else if (formOpen) {
      closeForm()
    } else {
      openForm('switch')
    }
  }

  function toggleNameSite() {
    if (!status?.service) return
    const current = status
    void run(() => saveEmailAliases({ service: current.service!, domain: current.domain, nameSite: !current.nameSite }))
  }
</script>

<div class="settings-list">
  <article>
    <div class="setting-copy">
      <strong>{status?.service ? serviceNames[status.service] : 'Create aliases from the login editor'}</strong>
      <p>{#if status?.service}{status.service === 'addy' ? `New aliases use ${status.domain ?? DEFAULT_ADDY_DOMAIN}. ` : ''}Your API token is kept in your vault, and Sesame sends it only to {serviceNames[status.service]} when you ask for an alias. Turning this off removes the token from your vault, but older backups and synced versions keep it, so revoke it at {serviceNames[status.service]} to stop it working.{:else}Sesame asks addy.io or SimpleLogin for a new forwarding address and puts it in the email field. It needs an API token from your account there.{/if}</p>
      {#if enabled && !formOpen}<button type="button" class="text-button replace-token" bind:this={replaceButton} disabled={working} on:click={() => openForm('replace')}>Replace token</button>{/if}
      {#if errorMessage && !formOpen}<p class="form-error" role="alert">{errorMessage}</p>{/if}
      {#if loadFailed && !known}<button type="button" class="text-button replace-token" on:click={load}>Try again</button>{/if}
    </div>
    <button type="button" class="switch" class:active={enabled} role="switch" aria-checked={enabled} aria-controls={formOpen ? 'alias-form' : undefined} aria-label="Email aliases" bind:this={switchButton} disabled={working || !known} on:click={toggle}><span></span></button>
  </article>
  {#if formOpen}
    <article class="settings-server-row">
      <form id="alias-form" class="setting-copy server-form alias-form" on:submit|preventDefault={save}>
        <label for="alias-service">Service</label>
        <SelectMenu id="alias-service" label="Service" value={service} options={serviceOptions} disabled={working} onChange={(value) => (service = value as EmailAliasService)} />
        <label for="alias-token">API token</label>
        <input id="alias-token" name="alias-token" type="password" bind:this={tokenInput} bind:value={token} aria-describedby={errorField === 'token' ? 'alias-token-help alias-form-error' : 'alias-token-help'} aria-invalid={errorField === 'token' ? 'true' : undefined} autocomplete="off" autocapitalize="off" spellcheck="false" disabled={working} />
        <p id="alias-token-help">{tokenHelp[service]}</p>
        {#if service === 'addy'}
          <label for="alias-domain">Alias domain</label>
          <input id="alias-domain" name="alias-domain" bind:value={domain} aria-describedby={errorField === 'domain' ? 'alias-form-error' : undefined} aria-invalid={errorField === 'domain' ? 'true' : undefined} autocomplete="off" autocapitalize="off" spellcheck="false" disabled={working} />
        {/if}
        {#if errorMessage}<p id="alias-form-error" class="form-error" role="alert">{errorMessage}</p>{/if}
        <div class="settings-service-actions">
          <button type="submit" class="secondary-button settings-manage" disabled={working || !token.trim()}>{working ? 'Saving…' : 'Save token'}</button>
          <button type="button" class="text-button" disabled={working} on:click={closeForm}>Cancel</button>
        </div>
      </form>
    </article>
  {/if}
  {#if status?.service}
    <article>
      <div class="setting-copy"><strong>Name the site</strong><p>Send the login's website, such as example.com, as the alias description so you can tell your aliases apart. When this is off, {serviceNames[status.service]} only learns that you made an alias.</p></div>
      <button type="button" class="switch" class:active={status.nameSite} role="switch" aria-checked={status.nameSite} aria-label="Name the site in alias descriptions" disabled={working} on:click={toggleNameSite}><span></span></button>
    </article>
  {/if}
</div>

<style>
  .alias-form :global(.sort-control) { display: block; }
  .alias-form :global(.sort-select-trigger) { width: 100%; height: auto; border: 1px solid var(--field-border); border-radius: var(--radius-sm); padding: 0 var(--space-3); min-height: 34px; color: var(--text); background: var(--field-bg); font-size: var(--type-2); font-weight: inherit; }
  .form-error { color: var(--danger); }
  .alias-form .form-error { margin: 0; }
  .replace-token { margin: var(--space-1) 0 0 calc(var(--space-1) * -1); }
</style>

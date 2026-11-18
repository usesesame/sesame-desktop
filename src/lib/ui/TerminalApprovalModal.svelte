<script module lang="ts">
  const SHOWN_BEFORE_ARMED_MS = 750
</script>

<script lang="ts">
  import { onDestroy } from 'svelte'
  import { approvalFooterText, createApprovalWait } from '../approval-wait'
  import { useAppStores } from '../stores/app-stores'
  import { getTerminalApprovalWait, type CliApprovalRequestEvent } from '../terminal-api'
  import { presenceCopy } from '../presence-copy'
  import { approvalHeading, approvalSummary, kindWords, noticeOnly, outputWords, secretNeeded, shownText } from '../terminal-text'
  import { vaultItems } from '../vault-items'
  import MasterPasswordField from './MasterPasswordField.svelte'
  import ModalShell from './ModalShell.svelte'

  export let request: CliApprovalRequestEvent
  export let onAllow: () => void
  export let onDeny: () => void
  export let onDismiss: () => void
  export let onExpire: (approvalId: string) => void
  export let onSelect: (itemId: string) => void
  export let onAllowTerminal: (checked: boolean) => void
  export let onSecret: (secret: string) => void

  const { terminalApproval, vault, settings } = useAppStores()
  const wait = createApprovalWait(getTerminalApprovalWait)
  const approvalId = request.approvalId
  const notFound = request.notFound !== undefined
  const missingField = !notFound && request.missingField
  const notice = noticeOnly(request)
  const choosing = !notice && request.candidates.length > 1

  let heldLongEnough = false
  const armTimer = window.setTimeout(() => (heldLongEnough = true), SHOWN_BEFORE_ARMED_MS)
  const remainingSeconds = () => Math.max(0, Math.ceil(($terminalApproval.expiresAt - Date.now()) / 1_000))
  let remaining = remainingSeconds()
  const timer = window.setInterval(() => {
    remaining = remainingSeconds()
    if (remaining === 0) onExpire(approvalId)
  }, 1_000)

  onDestroy(() => {
    window.clearTimeout(armTimer)
    window.clearInterval(timer)
  })

  $: state = $terminalApproval
  $: working = state.working
  $: askSecret = secretNeeded(request, state.selectedId, state.presenceGranted)
  $: secret = state.secret
  $: chosenValid = !choosing || request.candidates.some((candidate) => candidate.id === state.selectedId)
  $: armed = heldLongEnough && $wait.ms === 0
  $: lacksField = Boolean(request.field && resolved && !resolved.fieldName)
  $: allowDisabled = working || remaining === 0 || !armed || !chosenValid || lacksField || (askSecret && !secret)
  $: items = vaultItems($vault.snapshot)
  $: single = request.candidates.length === 1 ? request.candidates[0] : null
  $: resolved = single ?? request.candidates.find((candidate) => candidate.id === state.selectedId) ?? null
  $: askedDiffers = Boolean(request.field && resolved?.fieldName && request.field.trim().toLowerCase() !== resolved.fieldName.trim().toLowerCase())
  $: program = request.program ? shownText(request.program.reportedName, 48) : null
  $: presenceText = request.copy ? presenceCopy['copy-field'].description : presenceCopy['reveal-field'].description

  function details(id: string): string {
    const item = items.find((candidate) => candidate.id === id)
    if (!item) return ''
    return [item.subtitle, item.folder].filter(Boolean).map((part) => shownText(part, 40)).join(' · ')
  }

  function close() {
    if (working) return
    if (notice) onDismiss()
    else onDeny()
  }

  function allowTerminalChanged(event: Event & { currentTarget: HTMLInputElement }) {
    if (working || !armed) {
      event.currentTarget.checked = state.allowTerminal
      return
    }
    onAllowTerminal(event.currentTarget.checked)
  }

  function focusDialog(dialog: HTMLElement) {
    dialog.focus({ preventScroll: true })
  }
</script>

<ModalShell
  open={true}
  onClose={close}
  labelledby="terminal-approval-heading"
  describedby="terminal-approval-description"
  tone="terminal-approval"
  modalClass="terminal-approval-modal"
  initialFocus={focusDialog}
  ariaBusy={working}
>
  {#if notFound}
    <h2 id="terminal-approval-heading">A terminal asked for an item you do not have</h2>
    <p id="terminal-approval-description" class="terminal-summary">No item has the name below, so Sesame sends nothing back.</p>
  {:else if missingField}
    <h2 id="terminal-approval-heading">A terminal asked for a field this item does not have</h2>
    <p id="terminal-approval-description" class="terminal-summary">{request.candidates.length > 1 ? 'None of the items with this name has a' : 'The item below has no'} field by the name a terminal asked for, so Sesame sends nothing back.</p>
  {:else}
    <h2 id="terminal-approval-heading">{approvalHeading(request)}</h2>
    <p id="terminal-approval-description" class="terminal-summary">{approvalSummary(request)}</p>
  {/if}

  <dl class="terminal-request">
    {#if notFound}
      <div><dt>Name asked for</dt><dd><code class="terminal-value"><bdi>{shownText(request.notFound)}</bdi></code></dd></div>
    {:else if single}
      <div><dt>Item</dt><dd><span class="terminal-value"><bdi>{shownText(single.title)}</bdi></span><small>{kindWords(single.kind)}</small></dd></div>
    {:else if missingField}
      <div><dt>Items</dt><dd><span class="terminal-value"><bdi>{shownText(request.candidates[0].title)}</bdi></span><small>{request.candidates.length} items have this name</small></dd></div>
    {/if}
    {#if request.field}
      <div>
        <dt>Field</dt>
        <dd>
          {#if notice}
            <code class="terminal-value"><bdi>{shownText(request.field, 48)}</bdi></code>{#if missingField}<small>No field by that name</small>{/if}
          {:else if !resolved}
            <span>Choose an item to see which field it sends</span>
          {:else if resolved.fieldName}
            <span class="terminal-value terminal-field"><bdi>{shownText(resolved.fieldName, 48)}</bdi></span>{#if resolved.fieldHidden}<small>Hidden value</small>{/if}
            {#if askedDiffers}<small class="terminal-asked">Asked for as <code><bdi>{shownText(request.field, 48)}</bdi></code></small>{/if}
          {:else}
            <span>This item has no field by that name</span>
            <small class="terminal-asked">Asked for as <code><bdi>{shownText(request.field, 48)}</bdi></code></small>
          {/if}
        </dd>
      </div>
    {/if}
    {#if !notice && request.command !== 'list' && request.copy}
      <div><dt>Sent to</dt><dd><span>{outputWords(true, $settings.clipboardClearSeconds)}</span></dd></div>
    {/if}
    <div><dt>Terminal</dt><dd>{#if request.terminal}<code class="terminal-value"><bdi>{shownText(request.terminal, 24)}</bdi></code>{:else}<span>No terminal</span>{/if}{#if request.remote}<span class="status-pill warning">Remote session</span>{/if}</dd></div>
    <div><dt>Program</dt><dd>{#if program}<code class="terminal-value"><bdi>{program}</bdi></code><small>Name the program gave itself</small>{:else}<span>Not reported</span>{/if}</dd></div>
  </dl>

  {#if request.remote}
    <p class="terminal-note">This request came through a remote login such as SSH, not from a window on this computer.</p>
  {/if}

  {#if choosing}
    <fieldset class="terminal-choices" disabled={working}>
      <legend>Several items have this name. Choose one.</legend>
      {#each request.candidates as candidate (candidate.id)}
        <label class:selected={state.selectedId === candidate.id}>
          <input type="radio" name="terminal-choice" value={candidate.id} checked={state.selectedId === candidate.id} on:change={() => onSelect(candidate.id)} />
          <span>
            <strong><bdi>{shownText(candidate.title)}</bdi></strong>
            <small><bdi>{[kindWords(candidate.kind), details(candidate.id)].filter(Boolean).join(' · ')}</bdi></small>
            {#if request.field}<small class="terminal-choice-field">{#if candidate.fieldName}Sends <bdi>{shownText(candidate.fieldName, 48)}</bdi>{candidate.fieldHidden ? ', a hidden value' : ''}{:else}No field by that name{/if}</small>{/if}
          </span>
        </label>
      {/each}
    </fieldset>
  {/if}

  {#if request.allowed && choosing}
    <p class="terminal-note">This terminal is allowed right now, but Sesame still asks you to choose.</p>
  {/if}

  {#if askSecret && !notice}
    <div class="terminal-presence">
      <p>{presenceText}</p>
      <MasterPasswordField id="terminal-presence-password" value={secret} disabled={working} invalid={Boolean(state.error)} describedby={state.error ? 'terminal-approval-error' : undefined} onInput={onSecret} />
    </div>
  {/if}

  {#if request.canAllowTerminal && !notice}
    <label class="terminal-allow">
      <input type="checkbox" checked={state.allowTerminal} disabled={working || !armed} on:change={allowTerminalChanged} />
      <span><strong>Allow this terminal for five minutes</strong><small>Sesame answers it and any program started from it without asking, but hidden values still ask for your master password.</small></span>
    </label>
  {/if}

  {#if !notice || state.error}<p id="terminal-approval-error" class="form-error terminal-error" role="alert">{state.error}</p>{/if}

  <div class="terminal-footer modal-actions">
    {#if notice}
      <span></span>
      <div class="confirm-actions">
        <button type="button" class="primary-button" disabled={working} on:click={onDismiss}>OK</button>
      </div>
    {:else}
      <span>{approvalFooterText(remaining, $wait)}</span>
      <div class="confirm-actions">
        <button type="button" class="secondary-button" disabled={working} on:click={close}>Deny</button>
        <button type="button" class="primary-button" disabled={allowDisabled} on:click={onAllow}>{working ? 'Allowing…' : 'Allow'}</button>
      </div>
    {/if}
  </div>
</ModalShell>

<style>
  :global(.terminal-approval-modal) { width: min(100%, 540px); }
  :global(.terminal-approval-modal:focus) { outline: none; }
  :global(.terminal-approval-modal) h2 { margin: 0; color: var(--text-heading); font-size: var(--type-5); }
  .terminal-summary { margin: var(--space-2) 0 0; color: var(--text-muted); font-size: var(--type-3); line-height: 1.55; }
  .terminal-request { display: grid; margin: var(--space-4) 0 0; border-top: 1px solid var(--border-soft); }
  .terminal-request > div { display: grid; grid-template-columns: 8.5rem minmax(0, 1fr); align-items: baseline; gap: var(--space-3); border-bottom: 1px solid var(--border-soft); padding: var(--space-3) 0; }
  .terminal-request dt { color: var(--text-muted); font-size: var(--type-2); }
  .terminal-request dd { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--space-1) var(--space-2); min-width: 0; margin: 0; overflow: hidden; color: var(--text); font-size: var(--type-3); line-height: 1.7; }
  .terminal-request small { color: var(--text-muted); font-size: var(--type-2); }
  .terminal-asked { flex-basis: 100%; min-width: 0; overflow-wrap: anywhere; }
  .terminal-asked code { font-family: var(--font-code); }
  .terminal-request .status-pill { margin-left: 0; }
  .terminal-value { min-width: 0; max-width: 100%; color: var(--text); overflow-wrap: anywhere; unicode-bidi: isolate; }
  code.terminal-value { font-family: var(--font-code); font-size: var(--type-2); }
  bdi { unicode-bidi: isolate; }
  .terminal-note { margin: var(--space-3) 0 0; color: var(--text-muted); font-size: var(--type-2); line-height: 1.5; }
  .terminal-choices { display: grid; min-width: 0; margin: var(--space-4) 0 0; border: 0; padding: 0; }
  .terminal-choices legend { margin-bottom: var(--space-2); padding: 0; color: var(--text); font-size: var(--type-3); font-weight: var(--weight-medium); }
  .terminal-choices label { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: center; gap: var(--space-3); border-top: 1px solid var(--border-soft); padding: var(--space-3) var(--space-2); cursor: pointer; }
  .terminal-choices label:last-of-type { border-bottom: 1px solid var(--border-soft); }
  .terminal-choices label.selected { background: var(--tint); }
  .terminal-choices input { width: 16px; height: 16px; accent-color: var(--accent); }
  .terminal-choices label > span { display: grid; min-width: 0; gap: 2px; overflow: hidden; line-height: 1.7; }
  .terminal-choices strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .terminal-choices small { min-width: 0; overflow-wrap: anywhere; }
  .terminal-choices strong { color: var(--text); font-size: var(--type-3); font-weight: var(--weight-medium); }
  .terminal-choices small { color: var(--text-muted); font-size: var(--type-2); }
  .terminal-presence { margin-top: var(--space-4); }
  .terminal-presence p { margin: 0; color: var(--text-muted); font-size: var(--type-2); line-height: 1.5; }
  .terminal-presence :global(input) { width: 100%; margin-top: var(--space-2); border: 1px solid var(--field-border); border-radius: var(--radius-sm); padding: var(--space-3); color: var(--text); background: var(--field-bg); font-size: var(--type-3); outline: none; }
  .terminal-presence :global(input:focus-visible) { box-shadow: var(--field-ring); }
  .terminal-presence :global(label) { display: block; margin-top: var(--space-3); color: var(--text-2); font-size: var(--type-2); font-weight: var(--weight-bold); }
  .terminal-allow { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: start; gap: var(--space-3); margin-top: var(--space-4); cursor: pointer; }
  .terminal-allow input { margin-top: 2px; }
  .terminal-allow span { display: grid; gap: 2px; }
  .terminal-allow strong { color: var(--text); font-size: var(--type-3); font-weight: var(--weight-medium); }
  .terminal-allow small { color: var(--text-muted); font-size: var(--type-2); line-height: 1.5; }
  :global(.modal) .terminal-footer { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: var(--space-3) var(--space-4); margin-top: var(--space-5); border-top: 1px solid var(--border-soft); padding-top: var(--space-4); }
  :global(.modal) .terminal-request + .terminal-footer, :global(.modal) .terminal-request + .terminal-error + .terminal-footer { margin-top: var(--space-4); border-top: 0; padding-top: 0; }
  .terminal-error { min-height: calc(var(--type-2) * 1.45); margin: var(--space-3) 0 0; line-height: 1.45; }
  .terminal-footer > span { color: var(--text-muted); font-size: var(--type-2); }
  .terminal-footer .confirm-actions { margin: 0 0 0 auto; }
  @media (max-width: 520px) {
    .terminal-request > div { grid-template-columns: minmax(0, 1fr); gap: var(--space-1); }
    .terminal-error { min-height: calc(var(--type-2) * 1.45 * 2); }
  }
</style>

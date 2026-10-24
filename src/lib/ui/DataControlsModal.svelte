<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let dataActionWorking = false
  export let readableExportConfirmed = false
  export let completeExportConfirmed = false
  export let exportPresenceRequired = false
  export let exportPresencePassword = ''
  export let errorMessage = ''
  export let onClose: () => void
  export let onExportReadable: () => void
  export let onExportComplete: () => void
  export let onConfirmPresence: () => void
  export let onOpenDeleteVault: () => void

  function requestClose() {
    if (!dataActionWorking) onClose()
  }
</script>

<ModalShell
  open={true}
  onClose={requestClose}
  labelledby="data-controls-heading"
  describedby="data-controls-description"
  tone="data-controls"
  modalClass="data-controls-modal"
  ariaBusy={dataActionWorking}
>
  <button type="button" class="modal-close" disabled={dataActionWorking} on:click={requestClose} aria-label="Close data controls">×</button>
  <span class="data-controls-icon"><Icon name="archive" size={22} /></span>
  <h2 id="data-controls-heading">Export or remove your vault</h2>
  <p id="data-controls-description" class="sr-only">Manage readable exports and the local vault stored by Sesame on this device.</p>
  <section class="data-control-section"><div><h3>Complete export</h3><p>Creates one JSON file with every item in your vault, with all of its fields and secrets: logins, identities, secure notes, cards, Wi-Fi networks, SSH keys, licences, documents with their attachments, custom records, folders, and trash. Revision history is left out. The format is described in the repository so other tools can read it.</p><p>The file is not encrypted. An encrypted backup is the safer way to move your vault between Sesame installs.</p></div><label class="data-confirm"><input name="complete-export-confirmed" type="checkbox" bind:checked={completeExportConfirmed} /><span>I understand this export is not encrypted.</span></label><button type="button" class="secondary-button" disabled={!completeExportConfirmed || dataActionWorking} on:click={onExportComplete}>Export everything as JSON</button></section>
  <section class="data-control-section"><div><h3>Readable CSV export</h3><p>Creates a plain-text file of logins with names, website addresses, usernames, emails, passwords, folders, 2FA secrets, backup codes, recovery details, and notes. A second file holds any saved identities. Cards, secure notes, documents, SSH keys, Wi-Fi networks, licences, custom records, and trash are not in the CSV, so use the complete export to take them.</p><p>Open the file in a spreadsheet as data. A cell that starts with =, +, -, or @ can run as a formula. Store the files carefully.</p></div><label class="data-confirm"><input name="readable-export-confirmed" type="checkbox" bind:checked={readableExportConfirmed} /><span>I understand this export is not encrypted.</span></label><button type="button" class="secondary-button" disabled={!readableExportConfirmed || dataActionWorking} on:click={onExportReadable}>Export readable CSV</button></section>
  {#if exportPresenceRequired}
  <section class="data-control-section">
      <form class="presence-confirm" novalidate on:submit|preventDefault={onConfirmPresence}>
        <label class="delete-vault-input" for="export-presence-password">Master password</label>
        <input
          id="export-presence-password"
          name="export-presence-password"
          type="password"
          bind:value={exportPresencePassword}
          autocomplete="current-password"
          spellcheck="false"
          disabled={dataActionWorking}
          aria-invalid={Boolean(errorMessage)}
          aria-describedby={errorMessage ? 'export-presence-error' : undefined}
        />
        {#if errorMessage}<p id="export-presence-error" class="form-error" role="alert">{errorMessage}</p>{/if}
        <div class="confirm-actions">
          <button type="submit" class="secondary-button" disabled={!exportPresencePassword || dataActionWorking}>{dataActionWorking ? 'Confirming…' : 'Confirm and export'}</button>
        </div>
      </form>
  </section>
  {/if}
  <section class="data-control-section danger"><div><h3>Remove Sesame from this device</h3><p>Deletes the active vault, its previous copy, and Sesame's local backup folder. Export a backup first if you need this data.</p></div><button type="button" class="danger-button" disabled={dataActionWorking} on:click={onOpenDeleteVault}>Remove local vault</button></section>
</ModalShell>

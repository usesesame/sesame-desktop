<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let dataActionWorking = false
  export let readableExportConfirmed = false
  export let onClose: () => void
  export let onExportReadable: () => void
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
  <p class="eyebrow">Your local data</p>
  <h2 id="data-controls-heading">Export or remove your vault</h2>
  <p id="data-controls-description" class="sr-only">Manage readable exports and the local vault stored by Sesame on this device.</p>
  <section class="data-control-section"><div><h3>Readable CSV export</h3><p>Creates a plain-text file with passwords, 2FA secrets, recovery details, and notes. A second file is added for any saved identities. Store them carefully.</p></div><label class="data-confirm"><input type="checkbox" bind:checked={readableExportConfirmed} /><span>I understand this export is not encrypted.</span></label><button type="button" class="secondary-button" disabled={!readableExportConfirmed || dataActionWorking} on:click={onExportReadable}>Export readable CSV</button></section>
  <section class="data-control-section danger"><div><h3>Remove Sesame from this device</h3><p>Deletes the active vault, its previous copy, and Sesame's local backup folder. Export a backup first if you need this data.</p></div><button type="button" class="danger-button" disabled={dataActionWorking} on:click={onOpenDeleteVault}>Remove local vault</button></section>
</ModalShell>

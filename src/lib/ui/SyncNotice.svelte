<script lang="ts">
  import ModalShell from './ModalShell.svelte'

  export let onKeepOff: () => void
  export let onOpenSettings: () => void

  const focusKeepOff = (dialog: HTMLElement) => dialog.querySelector<HTMLButtonElement>('[data-keep-off]')?.focus()
</script>

<ModalShell onClose={onKeepOff} labelledby="sync-notice-heading" describedby="sync-notice-description" initialFocus={focusKeepOff}>
  <h2 id="sync-notice-heading">Sesame Sync is off</h2>
  <div id="sync-notice-description">
    <p class="modal-lede">
      Sync copies an encrypted vault between your own devices. Nothing is sent anywhere unless you
      turn it on, and your vault stays on this device until then.
    </p>
    <p class="modal-lede">
      Sync has not had an independent security review. You can read what it does and turn it on
      later in Settings, under Connections.
    </p>
  </div>
  <div class="modal-actions">
    <button type="button" class="secondary-button" on:click={onOpenSettings}>Open Sync settings</button>
    <button data-keep-off type="button" class="primary-button" on:click={onKeepOff}>Keep Sync off</button>
  </div>
</ModalShell>

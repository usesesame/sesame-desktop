<script lang="ts">
  import ModalShell from './ModalShell.svelte'
  import SetupProgress from './SetupProgress.svelte'

  export let onContinue: () => void
  export let onImport: () => void
  export let onAddLogin: () => void
  export let onOpenBackups: () => void

  const focusContinue = (dialog: HTMLElement) => dialog.querySelector<HTMLButtonElement>('[data-continue]')?.focus()
</script>

<ModalShell onClose={onContinue} labelledby="beta-onboarding-heading" describedby="beta-onboarding-description" tone="beta-onboarding" modalClass="beta-onboarding-modal" initialFocus={focusContinue}>
  <SetupProgress step={4} />
  <h2 id="beta-onboarding-heading">Your vault is ready</h2>
  <p id="beta-onboarding-description" class="beta-onboarding-intro">
    Sesame is still being tested. Your vault stays on this device unless you turn on Sync.
  </p>

  <ol class="beta-onboarding-steps">
    <li>
      <div>
        <strong>Bring in your logins</strong>
        <p>Import an export from your old password manager. Sesame lists what it kept and what it left out, so keep the old one until you have checked.</p>
      </div>
      <button type="button" class="text-button" on:click={onImport}>Import</button>
    </li>
    <li>
      <div>
        <strong>Save one login you use</strong>
        <p>Add it, then copy it or fill it from your browser to see how Sesame works day to day.</p>
      </div>
      <button type="button" class="text-button" on:click={onAddLogin}>Add a login</button>
    </li>
    <li>
      <div>
        <strong>Back up and prove it opens</strong>
        <p>Keep an encrypted backup somewhere other than this computer, then run the restore drill to check it.</p>
      </div>
      <button type="button" class="text-button" on:click={onOpenBackups}>Open backups</button>
    </li>
  </ol>

  <div class="beta-onboarding-actions">
    <button data-continue type="button" class="primary-button" on:click={onContinue}>Continue</button>
  </div>
</ModalShell>

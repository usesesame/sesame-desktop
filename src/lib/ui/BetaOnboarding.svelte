<script lang="ts">
  import Icon from '../Icon.svelte'
  import ModalShell from './ModalShell.svelte'

  export let onContinue: () => void
  export let onOpenBackups: () => void

  const focusContinue = (dialog: HTMLElement) => dialog.querySelector<HTMLButtonElement>('[data-continue]')?.focus()
</script>

<ModalShell onClose={onContinue} labelledby="beta-onboarding-heading" describedby="beta-onboarding-description" tone="beta-onboarding" modalClass="beta-onboarding-modal" initialFocus={focusContinue}>
  <span class="beta-onboarding-icon"><Icon name="shield" size={21} /></span>
  <p class="eyebrow">Public beta</p>
  <h2 id="beta-onboarding-heading">Before you add important logins</h2>
  <p id="beta-onboarding-description" class="beta-onboarding-intro">
    Sesame is still being tested. Your vault stays on this device and is not synced to a cloud account.
  </p>

  <ul class="beta-onboarding-list">
    <li><Icon name="archive" size={16} /><span>Keep an encrypted backup somewhere separate from this computer.</span></li>
    <li><Icon name="check" size={16} /><span>Test that you can restore a backup before relying on Sesame.</span></li>
  </ul>

  <div class="beta-onboarding-actions">
      <button type="button" class="secondary-button" on:click={onOpenBackups}>Open backups</button>
    <button data-continue type="button" class="primary-button" on:click={onContinue}>Continue</button>
  </div>
</ModalShell>

<script lang="ts">
  import SecretText from './SecretText.svelte'
  import { vaultText } from '../vault-text'
  import Icon from '../Icon.svelte'
  import type { CustomFieldEntry } from '../types'

  export let fields: CustomFieldEntry[] = []
  export let secretFields: string[] = []
  export let revealed: Record<string, string> = {}
  export let onCopy: (value: string, label: string) => void
  export let onCopyField: (key: string, label: string) => void
  export let onReveal: (key: string) => void
  export let onHide: (key: string) => void

  $: anyHidden = fields.some((field) => field.kind === 'secret')

  function slot(index: number): string {
    return `field:${index}`
  }
</script>

{#if fields.length}
  <section class="details-section login-fields" aria-labelledby="login-fields-detail-heading">
    <div class="section-heading"><h3 id="login-fields-detail-heading">Custom fields</h3></div>
    <div class="credentials-panel login-fields-panel">
      {#each fields as field, index (index)}
        {@const key = slot(index)}
        <div class="credential-row login-field-detail">
          <span class="credential-label" title={vaultText(field.label)}><span class="login-field-name"><bdi>{vaultText(field.label)}</bdi></span></span>
          {#if field.kind === 'secret'}
            {@const stored = secretFields.includes(key)}
            {@const shown = revealed[key] !== undefined}
            {#if !stored}
              <code class="login-field-empty">Empty</code>
            {:else if shown}
              <code class="revealed"><SecretText value={revealed[key]} /></code>
            {:else}
              <code class="concealed">••••••••••••••••</code>
            {/if}
            <button type="button" class="credential-button" aria-label={shown ? `Hide ${vaultText(field.label)}` : `Show ${vaultText(field.label)}`} title={shown ? `Hide ${vaultText(field.label)}` : `Show ${vaultText(field.label)}`} aria-pressed={shown} disabled={!stored} on:click={() => (shown ? onHide(key) : onReveal(key))}><Icon name={shown ? 'eye-off' : 'eye'} size={16} /></button>
            <button type="button" class="credential-button" aria-label={`Copy ${vaultText(field.label)}`} title={`Copy ${vaultText(field.label)}`} disabled={!stored} on:click={() => onCopyField(key, field.label)}><Icon name="copy" size={15} /></button>
          {:else}
            <code class:login-field-empty={!field.value}><bdi>{vaultText(field.value) || 'Empty'}</bdi></code>
            {#if anyHidden}<span class="login-field-spacer" aria-hidden="true"></span>{/if}
            <button type="button" class="credential-button" aria-label={`Copy ${vaultText(field.label)}`} title={`Copy ${vaultText(field.label)}`} disabled={!field.value} on:click={() => onCopy(field.value, field.label)}><Icon name="copy" size={15} /></button>
          {/if}
        </div>
      {/each}
    </div>
  </section>
{/if}

<style>
  .login-fields-panel { margin-top: var(--space-3); }
  .login-field-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .login-field-detail .credential-label { min-width: 0; }
  .login-field-empty { color: var(--text-muted); font-family: inherit; }
  .login-field-spacer { width: 32px; }
  @media (max-width: 680px) {
    .login-field-detail { grid-template-columns: minmax(0, 1fr) auto auto; row-gap: var(--space-1); }
    .login-field-detail .credential-label { grid-column: 1 / -1; }
  }
</style>

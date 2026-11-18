<script lang="ts">
  import { vaultText } from '../vault-text'
  import type { LegacyField } from '../types'

  export let fields: LegacyField[] = []
</script>

{#if fields.length}
  <section class="notes-section legacy-data" aria-label="Imported legacy data">
    <p class="eyebrow">Legacy data</p>
    <p class="field-hint">Imported fields are retained read-only. Secret values stay concealed.</p>
    {#each fields as field, index (index)}
      <p><strong><bdi>{vaultText(field.label)}</bdi></strong>: {#if field.secret}Secret value stored{:else}<bdi>{vaultText(field.value)}</bdi>{/if}</p>
    {/each}
  </section>
{/if}

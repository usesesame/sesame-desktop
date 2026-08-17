<script lang="ts">
  import type { LegacyField } from '../types'

  export let fields: LegacyField[] = []
</script>

{#if fields.length}
  <section class="notes-section legacy-data" aria-label="Imported legacy data">
    <p class="eyebrow">Legacy data</p>
    <p class="field-hint">Imported fields are retained read-only. Secret values stay concealed.</p>
    {#each fields as field, index (index)}
      <p><strong>{field.label}</strong>: {field.secret ? 'Secret value stored' : field.value}</p>
    {/each}
  </section>
{/if}

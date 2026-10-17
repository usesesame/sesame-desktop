<script lang="ts">
  import { isKept, withoutKept } from '../kept-secrets'

  export let draft: { keptSecrets?: string[] }
  export let key: string
  export let typed = ''
  export let onChange: (next: { keptSecrets?: string[] }) => void

  let removed = false

  function remove() {
    removed = true
    onChange(withoutKept(draft, key))
  }

  function keep() {
    removed = false
    onChange({ ...draft, keptSecrets: [...(draft.keptSecrets ?? []), key] })
  }
</script>

{#if !typed && removed}
  <p class="field-hint kept-secret">The saved value is removed when you save. <button type="button" class="text-button" on:click={keep}>Keep it</button></p>
{:else if !typed && isKept(draft, key)}
  <p class="field-hint kept-secret">A saved value stays as it is unless you type a new one. <button type="button" class="text-button" on:click={remove}>Remove it</button></p>
{/if}

<style>
  .kept-secret { margin: calc(var(--space-1) * -1) 0 var(--space-2); }
</style>

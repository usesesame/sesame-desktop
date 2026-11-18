<script lang="ts">
  import { onMount } from 'svelte'
  import { forgetNeverSaveSite, loadNeverSaveSites, neverSaveSites } from '../never-save-sites'
  import { messageFor } from '../controllers/feedback-controller'

  let working = ''
  let errorMessage = ''

  onMount(() => {
    loadNeverSaveSites().catch((error) => (errorMessage = messageFor(error)))
  })

  async function remove(origin: string) {
    if (working) return
    working = origin
    errorMessage = ''
    try {
      await forgetNeverSaveSite(origin)
    } catch (error) {
      errorMessage = messageFor(error)
    } finally {
      working = ''
    }
  }
</script>

<article>
  <div class="setting-copy">
    <strong>Sites Sesame never saves</strong>
    <p>Choose Never for this site when Sesame asks to save a login, and it stops asking on that address. Remove a site to be asked again.</p>
    {#if errorMessage}<p class="form-error" role="alert">{errorMessage}</p>{/if}
  </div>
  <span class="never-save-count">{$neverSaveSites?.length ? `${$neverSaveSites.length} ${$neverSaveSites.length === 1 ? 'site' : 'sites'}` : 'No sites'}</span>
</article>
{#each $neverSaveSites ?? [] as origin (origin)}
  <article class="never-save-row">
    <code>{#each origin.split(/(?<=[./:])/) as part, index (index)}{part}<wbr />{/each}</code>
    <button type="button" class="text-button" disabled={working !== ''} aria-label={`Remove ${origin}`} on:click={() => remove(origin)}>{working === origin ? 'Removing…' : 'Remove'}</button>
  </article>
{/each}

<style>
  .never-save-count { flex: none; color: var(--text-muted); font-size: var(--type-2); }
  .never-save-row code { flex: 1; min-width: 0; color: var(--text); font-family: var(--font-code); font-size: var(--type-2); }
</style>

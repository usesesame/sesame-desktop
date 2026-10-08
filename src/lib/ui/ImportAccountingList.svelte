<script lang="ts">
  import { accountingGroups, accountingNoun, keepSourceNote } from '../import-accounting'
  import type { ImportAccounting } from '../types'

  export let accounting: ImportAccounting
  export let authenticator: boolean

  $: groups = accountingGroups(accounting)
  $: note = keepSourceNote(accounting, authenticator)
</script>

<section class="import-accounting" aria-labelledby="import-accounting-heading">
  <h3 id="import-accounting-heading">What happens to each {accountingNoun(authenticator, 1)} in this file</h3>
  <ul>
    {#each groups as group (group.key)}
      <li>
        <span>{group.label}</span> <span class="import-accounting-count">{group.count}</span>
        {#if group.reasons.length > 0}
          <ul>
            {#each group.reasons as reason (reason.reason)}
              <li><span>{reason.label}</span> <span class="import-accounting-count">{reason.count}</span></li>
            {/each}
          </ul>
        {/if}
      </li>
    {/each}
    <li class="import-accounting-total"><span>In this file</span> <span class="import-accounting-count">{accounting.supplied}</span></li>
  </ul>
  {#if note}
    <p class="import-accounting-keep" role="note">{note}</p>
  {/if}
</section>

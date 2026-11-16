<script lang="ts">
  import { onMount } from 'svelte'
  import { cautionLine, hintLine } from '../release-record'
  import { getReleaseRecordHint } from '../release-record-api'
  import type { ReleaseRecordHint } from '../types'

  export let approvalId: string
  export let selectedId: string
  export let noun: string

  let hint: ReleaseRecordHint | null = null

  onMount(() => {
    void getReleaseRecordHint(approvalId)
      .then((loaded) => { if (loaded?.approvalId === approvalId) hint = loaded })
      .catch(() => { hint = null })
  })

  $: history = hintLine(hint, selectedId, noun)
  $: caution = cautionLine(hint)
</script>

{#if history || caution}
  <div class="approval-record">
    {#if history}<p>{history}</p>{/if}
    {#if caution}<p class="approval-caution">{caution}</p>{/if}
  </div>
{/if}

<script lang="ts">
  import LoginEditor from './LoginEditor.svelte'
  import type { LoginInput } from '../types'

  export let draft: LoginInput
  export let open = true
  export let onSubmit: (totpEntered: boolean) => void = () => {}

  export function reopen(next: LoginInput) {
    draft = next
    open = true
  }

  export function current(): LoginInput {
    return draft
  }
</script>

{#if open}
  <LoginEditor bind:loginDraft={draft} {onSubmit} onClose={() => (open = false)} onDelete={() => {}} />
{/if}

<script lang="ts">
  export let id: string
  export let value = ''
  export let invalid = false
  export let describedby: string | undefined = undefined
  export let disabled = false
  export let onInput: ((value: string) => void) | null = null
</script>

<label class="delete-vault-input" for={id}>Master password</label>
<input
  {id}
  name={id}
  type="password"
  bind:value
  autocomplete="current-password"
  spellcheck="false"
  {disabled}
  aria-invalid={invalid}
  aria-describedby={describedby}
  on:input={() => onInput?.(value)}
/>

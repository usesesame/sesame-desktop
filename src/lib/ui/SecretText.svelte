<script lang="ts">
  import { hasHiddenCharacters } from '../vault-text'

  export let value: string
</script>

<span class="secret-text"><bdi>{value}</bdi>{#if hasHiddenCharacters(value)}<small class="secret-text-note">Has an invisible or direction-changing character</small>{/if}</span>

<style>
  .secret-text { display: inline-grid; min-width: 0; max-width: 100%; gap: 2px; }
  .secret-text bdi { overflow: hidden; text-overflow: ellipsis; unicode-bidi: isolate; white-space: inherit; }
  .secret-text-note { color: var(--warn-text); font-family: var(--font-ui); font-size: var(--type-2); font-weight: var(--weight-medium); letter-spacing: normal; white-space: normal; }
</style>

<script lang="ts">
  import type { ActiveModal } from '../controllers/modal-controller'

  export let active: ActiveModal
</script>

{#if active}
  <div class="modal-host" role="presentation">
    <slot {active} />
  </div>
{/if}

<style>
  .modal-host {
    position: fixed;
    inset: 0;
    z-index: 100;
    display: grid;
    place-items: center;
    background: rgba(0, 0, 0, 0.35);
    backdrop-filter: blur(2px);
  }
</style>

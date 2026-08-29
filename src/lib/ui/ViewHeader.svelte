<script lang="ts">
  export let title: string
</script>

<header class="view-header">
  <div><h2>{title}</h2></div>
  <slot name="aside" />
</header>

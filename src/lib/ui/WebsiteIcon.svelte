<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { loadWebsiteIcon } from '../website-icons'

  export let site = ''
  export let initials = ''
  export let enabled = false

  let icon = ''
  let root: HTMLSpanElement
  let visible = false
  let requestToken = 0

  $: void refresh(site, enabled, visible)
  onMount(() => {
    if (!('IntersectionObserver' in window)) {
      visible = true
      return
    }
    const observer = new IntersectionObserver(([entry]) => {
      if (!entry?.isIntersecting) return
      visible = true
      observer.disconnect()
    }, { rootMargin: '160px' })
    observer.observe(root)
    return () => observer.disconnect()
  })
  onDestroy(() => { requestToken += 1 })

  async function refresh(nextSite: string, nextEnabled: boolean, inRange: boolean) {
    const token = ++requestToken
    icon = ''
    if (!nextEnabled || !inRange) return
    const loaded = await loadWebsiteIcon(nextSite)
    if (token === requestToken) icon = loaded
  }
</script>

<span bind:this={root} class="website-icon-content">{#if icon}<img src={icon} alt="" />{:else}{initials}{/if}</span>

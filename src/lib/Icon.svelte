<script lang="ts">
  export let name: string
  export let size = 18
  export let strokeWidth = 1.8
  export let label: string | undefined = undefined
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  preserveAspectRatio="xMidYMid meet"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  role={label ? 'img' : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : 'true'}
  focusable="false"
>
  {#if name === 'vault'}
    <rect x="3.5" y="4" width="17" height="16" rx="2.5" />
    <path d="M8 4v5h8V4M8 14h.01M12 14h.01M16 14h.01" />
  {:else if name === 'shield'}
    <path d="M12 3.5 19 6v5.1c0 4.2-2.7 7.6-7 9.4-4.3-1.8-7-5.2-7-9.4V6l7-2.5Z" />
    <path d="m9.3 12.1 1.8 1.8 3.8-4" />
  {:else if name === 'key'}
    <circle cx="8" cy="15.5" r="3.5" />
    <path d="m10.5 13 7.8-7.8M15.7 7.8l2.2 2.2M13.5 10l2.2 2.2" />
  {:else if name === 'archive'}
    <path d="M4 8.5h16v11H4zM3 4.5h18v4H3zM10 13h4" />
  {:else if name === 'folder'}
    <path d="M3.5 6.5A2.5 2.5 0 0 1 6 4h4l2 2h6A2.5 2.5 0 0 1 20.5 8.5v8A2.5 2.5 0 0 1 18 19H6a2.5 2.5 0 0 1-2.5-2.5Z" />
  {:else if name === 'folder-minus'}
    <path d="M3.5 6.5A2.5 2.5 0 0 1 6 4h4l2 2h6A2.5 2.5 0 0 1 20.5 8.5v8A2.5 2.5 0 0 1 18 19H6a2.5 2.5 0 0 1-2.5-2.5Z" />
    <path d="M9 13h6" />
  {:else if name === 'pencil'}
    <path d="m4 20 4.3-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.5 16.2Z" />
    <path d="m14.8 6.9 2.8 2.8M4 20l1.5-3.8 2.8 2.8Z" />
  {:else if name === 'trash'}
    <path d="M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5" />
  {:else if name === 'settings'}
    <path d="M4 7h2.8M11.2 7H20M4 17h8.8M17.2 17H20" />
    <circle cx="9" cy="7" r="2.2" />
    <circle cx="15" cy="17" r="2.2" />
  {:else if name === 'search'}
    <circle cx="10.7" cy="10.7" r="5.7" />
    <path d="m15 15 4.2 4.2" />
  {:else if name === 'plus'}
    <path d="M12 5v14M5 12h14" />
  {:else if name === 'copy'}
    <rect x="8" y="8" width="11" height="12" rx="2" />
    <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h2" />
  {:else if name === 'eye'}
    <path d="M2.7 12s3.2-5.5 9.3-5.5 9.3 5.5 9.3 5.5-3.2 5.5-9.3 5.5S2.7 12 2.7 12Z" />
    <circle cx="12" cy="12" r="2.4" />
  {:else if name === 'eye-off'}
    <path d="m3 3 18 18M10.6 6.7A10.8 10.8 0 0 1 12 6.5c6.1 0 9.3 5.5 9.3 5.5a17 17 0 0 1-3 3.6M6.5 8.2A17.2 17.2 0 0 0 2.7 12S5.9 17.5 12 17.5c1.4 0 2.7-.3 3.8-.8" />
    <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
  {:else if name === 'external'}
    <path d="M14 4h6v6M20 4l-9.5 9.5" />
    <path d="M18 13.5V19a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5.5" />
  {:else if name === 'more'}
    <circle cx="5" cy="12" r="1" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
    <circle cx="19" cy="12" r="1" fill="currentColor" stroke="none" />
  {:else if name === 'globe'}
    <circle cx="12" cy="12" r="8.5" />
    <path d="M3.5 12h17M12 3.5a13.5 13.5 0 0 1 0 17M12 3.5a13.5 13.5 0 0 0 0 17" />
  {:else if name === 'user'}
    <circle cx="12" cy="8" r="3.5" />
    <path d="M5 20c.8-3.3 3.2-5 7-5s6.2 1.7 7 5" />
  {:else if name === 'mail'}
    <rect x="3.5" y="5" width="17" height="14" rx="2" />
    <path d="m4.5 7 7.5 5.5L19.5 7" />
  {:else if name === 'phone'}
    <path d="M7.1 3.8 5 5.4c-1 1-1 3.2.2 6.1 1.3 3.2 4.1 6 7.3 7.3 2.9 1.2 5.1 1.2 6.1.2l1.6-2.1-3.3-3.3-2.2 1.4a11.1 11.1 0 0 1-4.8-4.8l1.4-2.2-3.2-3.2Z" />
  {:else if name === 'custom'}
    <path d="M4 7h16M4 12h16M4 17h10" />
    <circle cx="15" cy="7" r="1.6" fill="currentColor" stroke="none" />
    <circle cx="9" cy="12" r="1.6" fill="currentColor" stroke="none" />
    <circle cx="13" cy="17" r="1.6" fill="currentColor" stroke="none" />
  {:else if name === 'id-card'}
    <rect x="3" y="5.5" width="18" height="13" rx="2.2" />
    <circle cx="8.5" cy="11" r="2" />
    <path d="M6 15.5c.5-1.5 1.7-2.2 2.5-2.2s2 .7 2.5 2.2M14 9.5h4M14 12.5h4M14 15.5h2.5" />
  {:else if name === 'license'}
    <path d="M6 3.5h9l5 5V16H6z" />
    <path d="M15 3.5V8h5" />
    <circle cx="9.5" cy="15.5" r="2.2" />
    <path d="m8 19 1.5-1.5L11 19v-3.6M9.5 13.3v-.01" />
  {:else if name === 'wifi'}
    <path d="M4.5 10.2a11 11 0 0 1 15 0M7.4 13.3a7 7 0 0 1 9.2 0M10.3 16.3a3 3 0 0 1 3.4 0" />
    <circle cx="12" cy="19" r="1" fill="currentColor" stroke="none" />
  {:else if name === 'card'}
    <rect x="3" y="5.5" width="18" height="13" rx="2.2" />
    <path d="M3 9.5h18M6 14.5h4" />
  {:else if name === 'note'}
    <path d="M6 3.5h9l5 5V19a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 5 19V5a1.5 1.5 0 0 1 1.5-1.5Z" />
    <path d="M15 3.5V8h5M8.5 12h7M8.5 15.5h7" />
  {:else if name === 'file-key'}
    <path d="M6 3.5h8l4 4V20H6zM14 3.5v4h4" />
    <circle cx="10" cy="14" r="1.8" />
    <path d="M11.4 15.4 14.5 18M13 16.7l1.3-1.3" />
  {:else if name === 'chevron-right'}
    <path d="m9 5 7 7-7 7" />
  {:else if name === 'chevron-left'}
    <path d="m15 5-7 7 7 7" />
  {:else if name === 'check'}
    <path d="m5 12.5 4.2 4.2L19 7" />
  {:else if name === 'alert'}
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 8v4.5M12 16h.01" />
  {:else if name === 'lock'}
    <rect x="5" y="10" width="14" height="10" rx="2" />
    <path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10" />
  {:else if name === 'shield-alert'}
    <path d="M12 3.5 19 6v5.1c0 4.2-2.7 7.6-7 9.4-4.3-1.8-7-5.2-7-9.4V6l7-2.5Z" />
    <path d="M12 8.3v4.4M12 15.8h.01" />
  {:else if name === 'refresh'}
    <path d="M19 8.5A7.5 7.5 0 0 0 5.7 7M5 3.5v4h4M5 15.5A7.5 7.5 0 0 0 18.3 17M19 20.5v-4h-4" />
  {:else if name === 'sun'}
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2.5v2.5M12 19v2.5M4.6 4.6l1.8 1.8M17.6 17.6l1.8 1.8M2.5 12H5M19 12h2.5M4.6 19.4l1.8-1.8M17.6 6.4l1.8-1.8" />
  {:else if name === 'moon'}
    <path d="M20 13.5A8 8 0 0 1 9.5 4a7 7 0 1 0 10.5 9.5Z" />
  {:else if name === 'monitor'}
    <rect x="3" y="4.5" width="18" height="12" rx="2" />
    <path d="M8.5 20h7M12 16.5V20" />
  {:else if name === 'browser'}
    <rect x="3" y="4" width="18" height="16" rx="2.5" />
    <path d="M3 8.5h18" />
    <circle cx="6.5" cy="6.3" r=".55" fill="currentColor" stroke="none" />
    <circle cx="9" cy="6.3" r=".55" fill="currentColor" stroke="none" />
  {:else if name === 'help-circle'}
    <circle cx="12" cy="12" r="8.5" />
    <path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 3.2V14" />
    <circle cx="12" cy="17.2" r=".8" fill="currentColor" stroke="none" />
  {:else if name === 'keyboard'}
    <rect x="2.5" y="6" width="19" height="12.5" rx="2.2" />
    <path d="M6 10h.01M9.5 10h.01M13 10h.01M16.5 10h.01M6 14h9.5" />
  {:else if name === 'star'}
    <path d="M12 3.2l2.7 5.5 6 .9-4.3 4.2 1 6-5.4-2.9-5.4 2.9 1-6-4.3-4.2 6-.9Z" />
  {:else if name === 'star-filled'}
    <path fill="currentColor" stroke="none" d="M12 3.2l2.7 5.5 6 .9-4.3 4.2 1 6-5.4-2.9-5.4 2.9 1-6-4.3-4.2 6-.9Z" />
  {:else}
    <circle cx="12" cy="12" r="8" />
  {/if}
</svg>

<style>
  svg {
    display: block;
    flex: none;
    overflow: visible;
    shape-rendering: geometricPrecision;
  }
</style>

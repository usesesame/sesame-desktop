<script lang="ts">
  import type { BrowserIntegrationStatus } from '../types'
  import BrowserIntegrationSetting from './BrowserIntegrationSetting.svelte'
  import NeverSaveSitesSetting from './NeverSaveSitesSetting.svelte'

  export let browserIntegration: BrowserIntegrationStatus | null = null
  export let browserIntegrationWorking = false
  export let serviceConnectionAvailable = true
  export let onRefreshBrowserIntegration: () => void
  export let onRepairBrowserIntegration: () => void
</script>

<div class="settings-groups">
  {#if !browserIntegration?.ready || browserIntegration?.servedElsewhere}
    <section class="settings-group" aria-labelledby="settings-group-browser-extension">
      <h3 id="settings-group-browser-extension">Extension</h3>
      <div class="settings-list">
        <BrowserIntegrationSetting
          desktopAvailable={serviceConnectionAvailable}
          status={browserIntegration}
          working={browserIntegrationWorking}
          onRefresh={onRefreshBrowserIntegration}
          onRepair={onRepairBrowserIntegration}
        />
      </div>
    </section>
  {/if}
  <section class="settings-group" aria-labelledby="settings-group-browser-saving">
    <h3 id="settings-group-browser-saving">Saving</h3>
    <div class="settings-list">
      <NeverSaveSitesSetting />
    </div>
  </section>
</div>

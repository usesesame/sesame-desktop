<script lang="ts">
  import type { ServerInspection, ServiceConnectionStatus } from '../types'
  import AccountConnectionSetting from './AccountConnectionSetting.svelte'
  import CustomServerSetting from './CustomServerSetting.svelte'
  import SyncPanel from './SyncPanel.svelte'

  export let serviceConnection: ServiceConnectionStatus = { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }
  export let serviceWorking = false
  export let serviceConnectionAvailable = true
  export let onLinkService: (code: string) => void
  export let onInspectServer: (input: string) => Promise<ServerInspection | null>
  export let onConnectServer: (input: string, code: string, fingerprint: string) => Promise<boolean>
  export let onDisconnectService: () => void
  export let onRefreshService: () => void
</script>

<div class="settings-groups">
  {#if !serviceConnection.serverAddress}
    <section class="settings-group" aria-labelledby="settings-group-sync-account">
      <h3 id="settings-group-sync-account">Sesame account</h3>
      <div class="settings-list">
        <AccountConnectionSetting connection={serviceConnection} working={serviceWorking} available={serviceConnectionAvailable} onConnect={onLinkService} onDisconnect={onDisconnectService} onRefresh={onRefreshService} />
      </div>
    </section>
  {/if}
  <SyncPanel />
  <section class="settings-group" aria-labelledby="settings-group-sync-server">
    <h3 id="settings-group-sync-server">Your own server</h3>
    <div class="settings-list">
      <CustomServerSetting connection={serviceConnection} working={serviceWorking} available={serviceConnectionAvailable} onInspect={onInspectServer} onConnect={onConnectServer} onDisconnect={onDisconnectService} onRefresh={onRefreshService} />
    </div>
  </section>
</div>

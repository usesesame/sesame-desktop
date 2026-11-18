<script lang="ts">
  import { slidingSelection } from './sliding-selection'
  import { tick } from 'svelte'
  import Icon from '../Icon.svelte'
  import { SETTINGS_TABS, type SettingsTabId } from '../settings-tabs'
  import type { BrowserIntegrationStatus, DesktopUpdateProgress, DesktopUpdateStatus, DiagnosticStatus, RecoveryReplacementStatus, ServerInspection, ServiceConnectionStatus, Theme } from '../types'
  import GeneralSettings from './GeneralSettings.svelte'
  import SecuritySettings from './SecuritySettings.svelte'
  import BrowserSettings from './BrowserSettings.svelte'
  import SyncSettings from './SyncSettings.svelte'
  import ExtrasSettings from './ExtrasSettings.svelte'
  import DataSettings from './DataSettings.svelte'
  import PasswordPresenceModal from './PasswordPresenceModal.svelte'
  import IssuedRecoveryKitModal from './IssuedRecoveryKitModal.svelte'
  import ViewHeader from './ViewHeader.svelte'
  export let theme: Theme = 'auto'
  export let siteIconsEnabled = false
  export let autoLockMinutes = 5
  export let autoLockOptions: number[] = []
  export let clipboardClearSeconds = 30
  export let clipboardClearOptions: number[] = []
  export let onSetClipboardClearSeconds: (seconds: number) => void
  export let pinUnlockAvailable = false
  export let pinWorking = false
  export let onTogglePin: () => void
  export let helloUnlockAvailable = false
  export let helloWorking = false
  export let onToggleHello: () => void
  export let onChangeMasterPassword: () => void
  export let recoveryReplacement: RecoveryReplacementStatus | null = null
  export let recoveryWorking = false
  export let recoveryPresenceIntent: 'request-kit' | 'issue-kit' | null = null
  export let recoveryPresencePassword = ''
  export let recoveryPruneBackups = false
  export let issuedRecoveryKit = ''
  export let issuedRecoveryConfirmed = false
  export let issuedBackupsPruned = false
  export let issuedBackupsRemaining: number | null = null
  export let onRequestRecoveryKit: () => void = () => {}
  export let onIssueRecoveryKit: () => void = () => {}
  export let onCancelRecoveryRequest: () => void = () => {}
  export let onConfirmRecoveryPresence: () => void = () => {}
  export let onCancelRecoveryPresence: () => void = () => {}
  export let onFinishIssuedRecoveryKit: () => void = () => {}
  export let keepInTray = true
  export let trayWorking = false
  export let onToggleTray: () => void
  export let autostartEnabled = false
  export let autostartWorking = false
  export let onToggleAutostart: () => void
  export let screenCaptureAllowed = false
  export let screenCaptureKnown = true
  export let screenCaptureWorking = false
  export let onToggleScreenCapture: () => void = () => {}
  export let quickAccessShortcut = 'Ctrl+Alt+S'
  export let quickAccessShortcutWorking = false
  export let onUpdateQuickAccessShortcut: (accelerator: string) => void
  export let onSetTheme: (value: Theme) => void
  export let onSetSiteIconsEnabled: (enabled: boolean) => void
  export let siteIconsWorking = false
  export let siteIconsPresenceRequired = false
  export let siteIconsPresencePassword = ''
  export let errorMessage = ''
  export let onConfirmSiteIconsPresence: () => void
  export let onCancelSiteIconsPresence: () => void
  export let websiteIconCacheWorking = false
  export let websiteIconCacheEntryCount = 0
  export let websiteIconCacheIconCount = 0
  export let websiteIconCacheSizeBytes = 0
  export let onClearWebsiteIconCache: () => void
  export let onSetAutoLockMinutes: (minutes: number) => void
  export let onManageData: () => void
  export let diagnosticEventCount = 0
  export let diagnosticErrorCount = 0
  export let diagnosticWorking = false
  export let diagnosticStatus: DiagnosticStatus = { exists: false, eventCount: 0, errorCount: 0, sizeBytes: 0, localOnly: true, byOperation: [], byCode: [], recent: [] }
  export let onExportDiagnostics: () => void
  export let onClearDiagnostics: () => void
  export let serviceConnection: ServiceConnectionStatus = { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }
  export let serviceWorking = false
  export let onLinkService: (code: string) => void
  export let onInspectServer: (input: string) => Promise<ServerInspection | null>
  export let onConnectServer: (input: string, code: string, fingerprint: string) => Promise<boolean>
  export let onDisconnectService: () => void
  export let onRefreshService: () => void
  export let serviceConnectionAvailable = true
  export let desktopUpdate: DesktopUpdateStatus = { available: false }
  export let updateWorking = false
  export let updateProgress: DesktopUpdateProgress | null = null
  export let onCheckForUpdate: () => void
  export let onInstallUpdate: () => void
  export let browserIntegration: BrowserIntegrationStatus | null = null
  export let browserIntegrationWorking = false
  export let onRefreshBrowserIntegration: () => void
  export let onRepairBrowserIntegration: () => void

  const tabs = SETTINGS_TABS
  export let tab: SettingsTabId = 'general'
  const tabButtons: HTMLButtonElement[] = []
  let tabList: HTMLDivElement
  let moreBefore = false
  let moreAfter = false

  $: void revealTab(tab)

  async function revealTab(id: SettingsTabId) {
    await tick()
    const button = tabButtons[tabs.findIndex((item) => item.id === id)]
    if (!tabList || !button) return
    const margin = parseFloat(getComputedStyle(tabList).scrollPaddingInlineStart) || 0
    const start = button.offsetLeft - margin
    const end = button.offsetLeft + button.offsetWidth + margin
    if (start < tabList.scrollLeft) tabList.scrollLeft = Math.max(0, start)
    else if (end > tabList.scrollLeft + tabList.clientWidth) tabList.scrollLeft = end - tabList.clientWidth
    measureTabOverflow()
  }

  function measureTabOverflow() {
    if (!tabList) return
    moreBefore = tabList.scrollLeft > 1
    moreAfter = tabList.scrollLeft + tabList.clientWidth < tabList.scrollWidth - 1
  }

  async function handleTabKeydown(event: KeyboardEvent, index: number) {
    let nextIndex: number | null = null
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % tabs.length
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + tabs.length) % tabs.length
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = tabs.length - 1
    if (nextIndex === null) return

    event.preventDefault()
    tab = tabs[nextIndex].id
    await tick()
    tabButtons[nextIndex]?.focus()
  }
</script>

<svelte:window on:resize={() => void revealTab(tab)} />

<section class="settings-view">
  <ViewHeader title="Settings" />
  <div bind:this={tabList} class="settings-tabs" class:more-before={moreBefore} class:more-after={moreAfter} role="tablist" aria-label="Settings sections" use:slidingSelection on:scroll={measureTabOverflow}>
    {#each tabs as item, index (item.id)}
      <button
        bind:this={tabButtons[index]}
        id={`settings-tab-${item.id}`}
        role="tab"
        type="button"
        class:active={tab === item.id}
        aria-selected={tab === item.id}
        aria-controls={`settings-panel-${item.id}`}
        tabindex={tab === item.id ? 0 : -1}
        on:click={() => (tab = item.id)}
        on:keydown={(event) => handleTabKeydown(event, index)}
      >
        <Icon name={item.icon} size={15} strokeWidth={1.9} />{item.label}
      </button>
    {/each}
  </div>

  <div id={`settings-panel-${tab}`} class="settings-panel" role="tabpanel" aria-labelledby={`settings-tab-${tab}`}>
    {#key tab}
    {#if tab === 'general'}
      <GeneralSettings
        {theme}
        {onSetTheme}
        {siteIconsEnabled}
        {siteIconsWorking}
        {onSetSiteIconsEnabled}
        {websiteIconCacheWorking}
        {websiteIconCacheEntryCount}
        {websiteIconCacheIconCount}
        {websiteIconCacheSizeBytes}
        {onClearWebsiteIconCache}
        {keepInTray}
        {trayWorking}
        {onToggleTray}
        {autostartEnabled}
        {autostartWorking}
        {onToggleAutostart}
        {quickAccessShortcut}
        {quickAccessShortcutWorking}
        {onUpdateQuickAccessShortcut}
        {desktopUpdate}
        {updateWorking}
        {updateProgress}
        {onCheckForUpdate}
        {onInstallUpdate}
      />
    {:else if tab === 'security'}
      <SecuritySettings
        {autoLockMinutes}
        {autoLockOptions}
        {onSetAutoLockMinutes}
        {pinUnlockAvailable}
        {pinWorking}
        {onTogglePin}
        {helloUnlockAvailable}
        {helloWorking}
        {onToggleHello}
        {screenCaptureAllowed}
        {screenCaptureKnown}
        {screenCaptureWorking}
        {onToggleScreenCapture}
        {clipboardClearSeconds}
        {clipboardClearOptions}
        {onSetClipboardClearSeconds}
        {onChangeMasterPassword}
        {recoveryReplacement}
        {recoveryWorking}
        {onRequestRecoveryKit}
        {onIssueRecoveryKit}
        {onCancelRecoveryRequest}
      />
    {:else if tab === 'browser'}
      <BrowserSettings
        {browserIntegration}
        {browserIntegrationWorking}
        {serviceConnectionAvailable}
        {onRefreshBrowserIntegration}
        {onRepairBrowserIntegration}
      />
    {:else if tab === 'sync'}
      <SyncSettings
        {serviceConnection}
        {serviceWorking}
        {serviceConnectionAvailable}
        {onLinkService}
        {onInspectServer}
        {onConnectServer}
        {onDisconnectService}
        {onRefreshService}
      />
    {:else if tab === 'extras'}
      <ExtrasSettings />
    {:else if tab === 'data'}
      <DataSettings
        {onManageData}
        {diagnosticEventCount}
        {diagnosticErrorCount}
        {diagnosticWorking}
        {diagnosticStatus}
        {onExportDiagnostics}
        {onClearDiagnostics}
      />
    {/if}
    {/key}
  </div>
</section>

{#if recoveryPresenceIntent}
  <PasswordPresenceModal intent={recoveryPresenceIntent} bind:presenceSecret={recoveryPresencePassword} bind:pruneBackups={recoveryPruneBackups} errorMessage={errorMessage} onConfirm={onConfirmRecoveryPresence} onCancel={onCancelRecoveryPresence} />
{/if}
{#if issuedRecoveryKit}
  <IssuedRecoveryKitModal recoveryKit={issuedRecoveryKit} bind:confirmed={issuedRecoveryConfirmed} backupsPruned={issuedBackupsPruned} backupsRemaining={issuedBackupsRemaining} onDone={onFinishIssuedRecoveryKit} />
{/if}
{#if siteIconsPresenceRequired}
  <PasswordPresenceModal intent="enable-icons" bind:presenceSecret={siteIconsPresencePassword} errorMessage={errorMessage} onConfirm={onConfirmSiteIconsPresence} onCancel={onCancelSiteIconsPresence} />
{/if}

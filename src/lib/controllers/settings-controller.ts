import {
  nextTheme,
  readAutoLock,
  readBetaOnboardingDismissed,
  readClipboardClearSeconds,
  readRecoveryVerified,
  readSortMode,
  readKeepInTray,
  readQuickAccessShortcut,
  readSiteIcons,
  readTheme,
  resetOnboardingPreferences,
  storeAutoLock,
  storeBetaOnboardingDismissed,
  storeClipboardClearSeconds,
  storeRecoveryVerified,
  storeKeepInTray,
  storeQuickAccessShortcut,
  storeSiteIcons,
  storeTheme,
} from '../preferences'
import type { AppStores } from '../stores/app-stores'
import type { BrowserIntegrationStatus, DesktopUpdateProgress, DesktopUpdateStatus, DiagnosticStatus, ServiceConnectionStatus, Theme, WebsiteIconCacheStatus } from '../types'
import {
  changeMasterPassword,
	checkDesktopUpdate,
  clearDiagnostics,
  disableWindowsHello,
  disconnectService,
	downloadAndInstallDesktopUpdate,
  enableWindowsHello,
  exportDiagnostics,
  getAutostartEnabled,
  getBrowserIntegrationStatus,
	getDiagnosticStatus,
  getServiceConnectionStatus,
  getVaultStatus,
  getWebsiteIconCacheStatus,
	linkDesktopService,
	onDesktopUpdateProgress,
  previewMode,
  recordDiagnostic,
  removeUnlockPin,
  repairBrowserIntegration as repairBrowserConnection,
  setAutostartEnabled,
  setClipboardClearSeconds as setVaultClipboardClearSeconds,
  setNativeAutoLockMinutes,
  setQuickAccessShortcut,
  setTrayEnabled,
  setUnlockPin,
} from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'
import { clearCachedWebsiteIcons } from '../website-icons'

interface SettingsControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  onPinSetupFinished: () => void
}

const emptyDiagnostics: DiagnosticStatus = { exists: false, eventCount: 0, errorCount: 0, sizeBytes: 0, localOnly: true, byOperation: [], byCode: [], recent: [] }
const emptyService: ServiceConnectionStatus = { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }
const emptyWebsiteIconCache: WebsiteIconCacheStatus = { entryCount: 0, iconCount: 0, sizeBytes: 0 }

export function createSettingsController({ stores, feedback, modal, onPinSetupFinished }: SettingsControllerOptions) {
  const { selection, settings, vault } = stores
  const state = controllerStore({
    betaOnboardingOpen: false,
    betaOnboardingDismissed: false,
    recoveryVerified: false,
    preferenceLoaded: false,
    diagnosticStatus: emptyDiagnostics,
    diagnosticWorking: false,
    serviceConnection: emptyService,
    serviceWorking: false,
	updateStatus: { available: false } as DesktopUpdateStatus,
	updateWorking: false,
	updateProgress: null as DesktopUpdateProgress | null,
    browserIntegration: null as BrowserIntegrationStatus | null,
    browserIntegrationWorking: false,
    pinSetupOpen: false,
    pinSetupValue: '',
    pinSetupConfirm: '',
    pinWorking: false,
    helloWorking: false,
    trayWorking: false,
    quickAccessShortcutWorking: false,
    autostartEnabled: false,
    autostartWorking: false,
    websiteIconCacheWorking: false,
    websiteIconCache: emptyWebsiteIconCache,
    changeMasterPasswordOpen: false,
    currentMasterPassword: '',
    newMasterPassword: '',
    confirmNewMasterPassword: '',
    newRecoveryKit: '',
    newRecoveryConfirmed: false,
    changingMasterPassword: false,
  })
  let systemDark: MediaQueryList | undefined

  function applyTheme(value: Theme) {
    document.documentElement.dataset.theme = value === 'auto' ? (systemDark?.matches ? 'dark' : 'light') : value
  }

  async function refreshDiagnosticStatus() {
    try { state.patch({ diagnosticStatus: await getDiagnosticStatus() }) } catch { /* never block vault use */ }
  }

  async function refreshWebsiteIconCache() {
    try { state.patch({ websiteIconCache: await getWebsiteIconCacheStatus() }) } catch { /* non-critical */ }
  }

  async function refreshAutostartStatus() {
    try { state.patch({ autostartEnabled: await getAutostartEnabled() }) } catch { /* leave the last known state on screen */ }
  }

  async function refreshServiceConnection() {
    state.patch({ serviceWorking: true })
    try { state.patch({ serviceConnection: await getServiceConnectionStatus() }) } catch { /* local vault stays available */ }
    finally { state.patch({ serviceWorking: false }) }
  }

  async function checkForUpdate(userInitiated = false) {
    state.patch({ updateWorking: true })
    try {
      const updateStatus = await checkDesktopUpdate()
      state.patch({ updateStatus })
      // Silence reads as a broken button to someone who just pressed it, so a
      // check nobody asked for stays quiet and a check someone did gets an answer.
      if (userInitiated && !updateStatus.available) {
        feedback.showNotice('No update available', 'You are running the latest version of Sesame.')
      }
    }
    catch (error) { if (userInitiated) feedback.setError(error) }
    finally { state.patch({ updateWorking: false }) }
  }

  async function installUpdate() {
	state.patch({ updateWorking: true, updateProgress: { downloadedBytes: 0 } })
    try { await downloadAndInstallDesktopUpdate() }
    catch (error) { feedback.setError(error); state.patch({ updateWorking: false }) }
  }

  async function refreshBrowserIntegration(reportFailure = false) {
    state.patch({ browserIntegrationWorking: true })
    try {
      state.patch({ browserIntegration: await getBrowserIntegrationStatus() })
    } catch (error) {
      state.patch({ browserIntegration: null })
      void recordDiagnostic('browser_host', 'registration_status_failed')
      if (reportFailure) feedback.setError(error)
    } finally {
      state.patch({ browserIntegrationWorking: false })
    }
  }

  function browserIntegrationMessage(result: BrowserIntegrationStatus) {
    if (result.code === 'hostMissing') return 'This Sesame installation is missing its browser connection component. Reinstall or repair the desktop app.'
    if (result.code === 'manifestMissing') return 'Sesame could not create the browser connection files.'
    if (result.code === 'registrationMissing') return 'Sesame could not register the browser connection for this Windows profile.'
    return 'Browser connection is not supported on this device.'
  }

  function clearMasterPasswordState() {
    state.patch({
      changeMasterPasswordOpen: false, currentMasterPassword: '', newMasterPassword: '',
      confirmNewMasterPassword: '', newRecoveryKit: '', newRecoveryConfirmed: false, changingMasterPassword: false,
    })
  }

  function dismissOnboarding() {
    state.patch({ betaOnboardingOpen: false, betaOnboardingDismissed: true })
    storeBetaOnboardingDismissed()
  }

  function markRecoveryVerified() {
    state.patch({ recoveryVerified: true })
    storeRecoveryVerified()
  }

  function setTheme(value: Theme) {
    settings.patch({ theme: value })
    storeTheme(value)
    applyTheme(value)
  }

  function openPinSetup() {
    state.patch({ pinSetupValue: '', pinSetupConfirm: '' })
    feedback.clearError()
    modal.open({ kind: 'pin-setup' })
  }

  return {
    state,
    refreshDiagnosticStatus,
    refreshServiceConnection,
    checkForUpdate,
    installUpdate,
    refreshBrowserIntegration,
    refreshWebsiteIconCache,
    start() {
      settings.patch({
        theme: readTheme() ?? 'auto', siteIconsEnabled: readSiteIcons(),
        autoLockMinutes: readAutoLock(), clipboardClearSeconds: readClipboardClearSeconds(),
        keepInTray: readKeepInTray(),
        quickAccessShortcut: readQuickAccessShortcut(),
      })
      setVaultClipboardClearSeconds(settings.value().clipboardClearSeconds)
      selection.patch({ sortMode: readSortMode() })
      state.patch({
        betaOnboardingDismissed: readBetaOnboardingDismissed(),
        recoveryVerified: readRecoveryVerified(),
        preferenceLoaded: true,
      })
      systemDark = window.matchMedia('(prefers-color-scheme: dark)')
      const onScheme = () => { if (settings.value().theme === 'auto') applyTheme('auto') }
      systemDark.addEventListener('change', onScheme)
      applyTheme(settings.value().theme)
      if (!previewMode) {
        void setTrayEnabled(settings.value().keepInTray).catch(() => {})
        void setNativeAutoLockMinutes(settings.value().autoLockMinutes).catch(() => feedback.setErrorMessage('Sesame could not apply the automatic lock setting.'))
        void setQuickAccessShortcut(settings.value().quickAccessShortcut).catch(() => {})
      }
      void refreshDiagnosticStatus()
      void refreshWebsiteIconCache()
      void refreshServiceConnection()
      void refreshBrowserIntegration()
      void refreshAutostartStatus()
      let stopUpdateProgress = () => {}
      void onDesktopUpdateProgress((progress) => state.patch({ updateProgress: progress })).then((stop) => { stopUpdateProgress = stop })
      return () => {
        systemDark?.removeEventListener('change', onScheme)
        stopUpdateProgress()
      }
    },
    showOnboardingIfNeeded() {
      const current = state.value()
      if (
        current.preferenceLoaded
        && vault.value().status.unlocked
        && !current.betaOnboardingDismissed
        && !current.betaOnboardingOpen
        && !current.pinSetupOpen
        && !current.changeMasterPasswordOpen
      ) {
        state.patch({ betaOnboardingOpen: true })
      }
    },
    dismissOnboarding,
    markRecoveryVerified,
    resetOnboarding() {
      resetOnboardingPreferences()
      state.patch({ betaOnboardingOpen: false, betaOnboardingDismissed: false, recoveryVerified: false })
    },
    openBackupsFromOnboarding() {
      dismissOnboarding()
      selection.patch({ activeView: 'backups' })
    },
    setTheme,
    cycleTheme() {
      setTheme(nextTheme(settings.value().theme))
    },
    setSiteIconsEnabled(enabled: boolean) {
      settings.patch({ siteIconsEnabled: enabled })
      storeSiteIcons(enabled)
      feedback.showNotice(enabled ? 'Website icons enabled' : 'Website icons disabled', enabled ? 'Sesame will reuse each downloaded icon for up to 30 days.' : 'Saved logins will use their initials instead.')
    },
    async clearWebsiteIcons() {
      if (state.value().websiteIconCacheWorking) return
      state.patch({ websiteIconCacheWorking: true })
      feedback.clearError()
      try {
        await clearCachedWebsiteIcons()
        state.patch({ websiteIconCache: emptyWebsiteIconCache })
        feedback.showNotice('Website icon cache cleared', 'Icons will be downloaded again only when the feature is enabled and the vault view needs them.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ websiteIconCacheWorking: false })
      }
    },
    setAutoLockMinutes(minutes: number) {
      settings.patch({ autoLockMinutes: minutes })
      storeAutoLock(minutes)
      void setNativeAutoLockMinutes(minutes).catch(() => feedback.setErrorMessage('Sesame could not apply the automatic lock setting.'))
      feedback.showNotice('Automatic lock updated', `Locks after ${minutes} ${minutes === 1 ? 'minute' : 'minutes'} of inactivity.`)
    },
    setClipboardClearSeconds(seconds: number) {
      settings.patch({ clipboardClearSeconds: seconds })
      storeClipboardClearSeconds(seconds)
      setVaultClipboardClearSeconds(seconds)
      feedback.showNotice('Clipboard timeout updated', `Copied values clear after ${seconds} seconds.`)
    },
    openPinSetup,
    closePinSetup() {
      if (state.value().pinWorking) return
      modal.close('pin-setup')
      state.patch({ pinSetupValue: '', pinSetupConfirm: '' })
      feedback.clearError()
      onPinSetupFinished()
    },
    async savePin() {
      const current = state.value()
      if (current.pinWorking) return
      if (!/^\d{6}$/.test(current.pinSetupValue)) return feedback.setErrorMessage('Use exactly six digits.')
      if (current.pinSetupValue !== current.pinSetupConfirm) return feedback.setErrorMessage('Those PINs do not match.')
      state.patch({ pinWorking: true })
      feedback.clearError()
      try {
        await setUnlockPin(current.pinSetupValue)
        vault.patch({ status: await getVaultStatus() })
        modal.close('pin-setup')
        state.patch({ pinSetupValue: '', pinSetupConfirm: '' })
        feedback.showNotice('PIN saved', 'Use it the next time you unlock.')
        onPinSetupFinished()
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ pinWorking: false })
      }
    },
    async togglePinUnlock() {
      if (state.value().pinWorking) return
      if (!vault.value().status.pinUnlockAvailable) return openPinSetup()
      state.patch({ pinWorking: true })
      feedback.clearError()
      try {
        await removeUnlockPin()
        vault.patch({ status: await getVaultStatus() })
        feedback.showNotice('PIN removed', 'Your master password or recovery kit is required next time.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ pinWorking: false })
      }
    },
    async toggleHelloUnlock() {
      if (state.value().helloWorking) return
      state.patch({ helloWorking: true })
      feedback.clearError()
      try {
        if (vault.value().status.helloUnlockAvailable) {
          await disableWindowsHello()
          vault.patch({ status: await getVaultStatus() })
          feedback.showNotice('Windows Hello unlock removed', 'Your master password or recovery kit is required next time.')
        } else {
          await enableWindowsHello()
          vault.patch({ status: await getVaultStatus() })
          feedback.showNotice('Windows Hello unlock enabled', 'Use it the next time you unlock.')
        }
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ helloWorking: false })
      }
    },
    async toggleTray() {
      if (state.value().trayWorking) return
      const next = !settings.value().keepInTray
      state.patch({ trayWorking: true })
      feedback.clearError()
      try {
        await setTrayEnabled(next)
        settings.patch({ keepInTray: next })
        storeKeepInTray(next)
        feedback.showNotice(next ? 'Tray enabled' : 'Tray disabled', next ? 'Closing the window keeps it in the tray.' : 'Closing the window quits the app.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ trayWorking: false })
      }
    },
    async updateQuickAccessShortcut(accelerator: string) {
      if (state.value().quickAccessShortcutWorking) return
      state.patch({ quickAccessShortcutWorking: true })
      feedback.clearError()
      try {
        await setQuickAccessShortcut(accelerator)
        settings.patch({ quickAccessShortcut: accelerator })
        storeQuickAccessShortcut(accelerator)
        feedback.showNotice('Shortcut updated', `Quick access now opens with ${accelerator}.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ quickAccessShortcutWorking: false })
      }
    },
    refreshAutostartStatus,
    async toggleAutostart() {
      if (state.value().autostartWorking) return
      const next = !state.value().autostartEnabled
      state.patch({ autostartWorking: true })
      feedback.clearError()
      try {
        await setAutostartEnabled(next)
        state.patch({ autostartEnabled: next })
        feedback.showNotice(next ? 'Starts with Windows' : 'Startup entry removed', next ? 'Sesame opens in the tray next time Windows starts, and stays locked until you unlock it.' : 'Sesame no longer opens automatically.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ autostartWorking: false })
      }
    },
    openChangeMasterPassword() {
      clearMasterPasswordState()
      modal.open({ kind: 'change-master-password' })
      feedback.clearError()
    },
    cancelChangeMasterPassword() {
      const current = state.value()
      if (current.changingMasterPassword) return
      // The kit on screen is the only one that still opens this vault; cancel must not discard it.
      if (current.newRecoveryKit) return
      modal.close('change-master-password')
      clearMasterPasswordState()
      feedback.clearError()
    },
    async saveChangedMasterPassword() {
      const current = state.value()
      if (current.changingMasterPassword) return
      if (current.newMasterPassword.length < 12) return feedback.setErrorMessage('Use a new master password with at least 12 characters.')
      if (current.newMasterPassword !== current.confirmNewMasterPassword) return feedback.setErrorMessage('Those new passwords do not match.')
      state.patch({ changingMasterPassword: true })
      feedback.clearError()
      try {
        const result = await changeMasterPassword(current.currentMasterPassword, current.newMasterPassword)
        vault.patch({ status: await getVaultStatus() })
        state.patch({ currentMasterPassword: '', newMasterPassword: '', confirmNewMasterPassword: '', newRecoveryKit: result.recoveryKit })
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ changingMasterPassword: false })
      }
    },
    finishMasterPasswordChange() {
      if (!state.value().newRecoveryConfirmed) return
      modal.close('change-master-password')
      clearMasterPasswordState()
      feedback.showNotice('Master password changed', 'Your vault has a new encryption key and recovery kit. PIN and Windows Hello unlock can be enabled again in Settings.')
    },
    async repairBrowserIntegration() {
      state.patch({ browserIntegrationWorking: true })
      feedback.clearError()
      try {
        const result = await repairBrowserConnection()
        state.patch({ browserIntegration: result })
        if (result.ready) feedback.showNotice('Desktop browser connection repaired', 'The native connection is registered. This does not confirm that the browser extension is installed.')
        else {
          feedback.setErrorMessage(browserIntegrationMessage(result))
          const code = result.code === 'hostMissing' ? 'registration_host_missing'
            : result.code === 'manifestMissing' ? 'registration_manifest_failed'
              : result.code === 'registrationMissing' ? 'registration_registry_failed' : 'registration_unsupported'
          void recordDiagnostic('browser_host', code)
        }
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ browserIntegrationWorking: false })
      }
    },
    async connectService(code: string) {
      state.patch({ serviceWorking: true })
      feedback.clearError()
      try {
        state.patch({ serviceConnection: await linkDesktopService(code) })
        feedback.showNotice('Desktop connected', 'This Windows desktop is linked to your Sesame account. Sync is still unavailable.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ serviceWorking: false })
      }
    },
    async unlinkService() {
      state.patch({ serviceWorking: true })
      feedback.clearError()
      try {
        await disconnectService()
        state.patch({ serviceConnection: emptyService })
        feedback.showNotice('Desktop disconnected', 'The account connection was removed from this Windows profile. Your vault is unchanged.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ serviceWorking: false })
      }
    },
    async exportLocalDiagnostics() {
      state.patch({ diagnosticWorking: true })
      try {
        const fileName = await exportDiagnostics()
        if (fileName) feedback.showNotice('Diagnostics exported', `${fileName} contains event categories only. Review it before sharing.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ diagnosticWorking: false })
        void refreshDiagnosticStatus()
      }
    },
    async clearLocalDiagnostics() {
      state.patch({ diagnosticWorking: true })
      try {
        await clearDiagnostics()
        state.patch({ diagnosticStatus: emptyDiagnostics })
        feedback.showNotice('Diagnostics cleared', 'The diagnostic log was removed.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ diagnosticWorking: false })
      }
    },
    clearSecrets() {
      modal.closeAll()
      state.patch({
        pinSetupValue: '', pinSetupConfirm: '', pinWorking: false, helloWorking: false,
        currentMasterPassword: '', newMasterPassword: '',
        confirmNewMasterPassword: '', newRecoveryKit: '', newRecoveryConfirmed: false,
        changingMasterPassword: false,
      })
    },
  }
}

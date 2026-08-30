<script lang="ts">
  import { onMount } from 'svelte'
  import { autoLockOptions, clipboardClearOptions } from './lib/preferences'
  import { isSortMode } from './lib/vault-collections'
  import { vaultItems } from './lib/vault-items'
  import { createAppStores, provideAppStores } from './lib/stores/app-stores'
  import { exportRecoveryKit, onIdleWarning, onIdleWarningCleared, onQuickAccessOpenItem, openWebsite, previewMode, recordDiagnostic } from './lib/vault'
  import { loadPlatformCapabilities } from './lib/platform'
  import type { ImportSource, NavigationGroup, View } from './lib/types'
  import { storeSortMode } from './lib/preferences'
  import { createFeedbackController } from './lib/controllers/feedback-controller'
  import { createLoginController } from './lib/controllers/login-controller'
  import { createImportController } from './lib/controllers/import-controller'
  import { createBrowserFillController } from './lib/controllers/browser-fill-controller'
  import { createIdentityFillController } from './lib/controllers/identity-fill-controller'
  import { createCardFillController } from './lib/controllers/card-fill-controller'
  import { createBrowserSaveController } from './lib/controllers/browser-save-controller'
  import { createSettingsController } from './lib/controllers/settings-controller'
  import { createBackupController } from './lib/controllers/backup-controller'
  import { createCleanupController } from './lib/controllers/cleanup-controller'
  import { createUnlockController } from './lib/controllers/unlock-controller'
  import { createIdentityController } from './lib/controllers/identity-controller'
  import { createSecureNoteController } from './lib/controllers/secure-note-controller'
  import { createCardController } from './lib/controllers/card-controller'
  import { createWifiNetworkController } from './lib/controllers/wifi-network-controller'
  import { createSshKeyController } from './lib/controllers/ssh-key-controller'
  import { createSoftwareLicenseController } from './lib/controllers/software-license-controller'
  import { createDocumentController } from './lib/controllers/document-controller'
  import { createCustomRecordController } from './lib/controllers/custom-record-controller'
  import { createItemController } from './lib/controllers/item-controller'
  import { createTrashController } from './lib/controllers/trash-controller'
  import { createHistoryController } from './lib/controllers/history-controller'
  import { createModalController } from './lib/controllers/modal-controller'
  import { createOnboardingController } from './lib/controllers/onboarding-controller'
  import AppChrome from './lib/ui/AppChrome.svelte'
  import ModalHost from './lib/ui/ModalHost.svelte'
  import WorkspaceShell from './lib/ui/WorkspaceShell.svelte'
  import UnlockScreen from './lib/ui/UnlockScreen.svelte'
  import WelcomeScreen from './lib/ui/WelcomeScreen.svelte'
  import RecoveryKitScreen from './lib/ui/RecoveryKitScreen.svelte'
  import ImportModal from './lib/ui/ImportModal.svelte'
  import LoginEditor from './lib/ui/LoginEditor.svelte'
  import IdentityEditor from './lib/ui/IdentityEditor.svelte'
  import RestoreModal from './lib/ui/RestoreModal.svelte'
  import BackupDrillModal from './lib/ui/BackupDrillModal.svelte'
  import DataControlsModal from './lib/ui/DataControlsModal.svelte'
  import DeleteVaultModal from './lib/ui/DeleteVaultModal.svelte'
  import ConfirmDeleteModal from './lib/ui/ConfirmDeleteModal.svelte'
  import SecureNoteEditor from './lib/ui/SecureNoteEditor.svelte'
  import CardEditor from './lib/ui/CardEditor.svelte'
  import ConfirmDeleteRecordModal from './lib/ui/ConfirmDeleteRecordModal.svelte'
  import WifiNetworkEditor from './lib/ui/WifiNetworkEditor.svelte'
  import SshKeyEditor from './lib/ui/SshKeyEditor.svelte'
  import SoftwareLicenseEditor from './lib/ui/SoftwareLicenseEditor.svelte'
  import DocumentEditor from './lib/ui/DocumentEditor.svelte'
  import CustomRecordEditor from './lib/ui/CustomRecordEditor.svelte'
  import ConfirmMergeModal from './lib/ui/ConfirmMergeModal.svelte'
  import VaultView from './lib/ui/VaultView.svelte'
  import CheckupView from './lib/ui/CheckupView.svelte'
  import ToolsView from './lib/ui/ToolsView.svelte'
  import AuthenticatorView from './lib/ui/AuthenticatorView.svelte'
  import BackupsView from './lib/ui/BackupsView.svelte'
  import TrashView from './lib/ui/TrashView.svelte'
  import HistoryView from './lib/ui/HistoryView.svelte'
  import SettingsView from './lib/ui/SettingsView.svelte'
  import BetaOnboarding from './lib/ui/BetaOnboarding.svelte'
  import BrowserFillApprovalModal from './lib/ui/BrowserFillApprovalModal.svelte'
  import BrowserIdentityFillApprovalModal from './lib/ui/BrowserIdentityFillApprovalModal.svelte'
  import BrowserCardFillApprovalModal from './lib/ui/BrowserCardFillApprovalModal.svelte'
  import BrowserSaveApprovalModal from './lib/ui/BrowserSaveApprovalModal.svelte'
  import PinSetupModal from './lib/ui/PinSetupModal.svelte'
  import ChangeMasterPasswordModal from './lib/ui/ChangeMasterPasswordModal.svelte'
  import EntryContextMenu from './lib/ui/EntryContextMenu.svelte'
  import FolderManagerModal from './lib/ui/FolderManagerModal.svelte'
  import FolderNameModal from './lib/ui/FolderNameModal.svelte'

  const appStores = provideAppStores(createAppStores())
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- the import flow reads the store through the controller.
  const { browserFill, browserIdentityFill, browserCardFill, browserSave, generator, imports, passphrase, recentGenerations, selection, settings, totp, vault } = appStores
  vault.patch({ status: { exists: false, unlocked: false, preview: previewMode, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 0 } })

  const feedbackController = createFeedbackController()
  const feedbackState = feedbackController.state
  let refreshDiagnostics = async () => {}
  let requestDelete = (_entry: Parameters<ReturnType<typeof createCleanupController>['requestDelete']>[0]) => {}
  let requestBulkDelete = (_entries: Parameters<ReturnType<typeof createCleanupController>['requestBulkDelete']>[0]) => {}
  let onVaultDeleted = (_message: string) => {}
  let onRestored = (_message: string) => {}
  let onNativeVaultLocked = () => {}
  let onPinSetupFinished = () => {}

  const modalController = createModalController({
    stores: appStores,
    feedback: feedbackController,
  })
  const modalState = modalController.state

  const loginController = createLoginController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
    refreshDiagnostics: () => refreshDiagnostics(),
    requestDelete: (entry) => requestDelete(entry),
    requestBulkDelete: (entries) => requestBulkDelete(entries),
  })
  const loginState = loginController.state
  const folderOptions = loginController.folderOptions
  const contextEntry = loginController.contextEntry

  const settingsController = createSettingsController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
    onPinSetupFinished: () => onPinSetupFinished(),
  })
  const settingsState = settingsController.state
  refreshDiagnostics = settingsController.refreshDiagnosticStatus

  const onboardingController = createOnboardingController({
    stores: appStores,
    onOpenPinSetup: () => settingsController.openPinSetup(),
    onRecoveryVerified: () => settingsController.markRecoveryVerified(),
  })
  const onboardingState = onboardingController.state
  let setupWelcomeSeen = false
  let authenticatorReloadToken = 0
  onPinSetupFinished = () => {
    if (onboardingState.value().step === 'pin-choice') onboardingController.advance()
  }

  const importController = createImportController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
    refreshDiagnostics: settingsController.refreshDiagnosticStatus,
    selectEntry: loginController.selectEntry,
  })

  const cleanupController = createCleanupController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
    selectEntry: loginController.selectEntry,
    editEntry: async (entry) => {
      await loginController.selectEntry(entry.id)
      loginController.openEditor()
    },
    clearLoginSelection: loginController.clearSelection,
    refreshDiagnostics: settingsController.refreshDiagnosticStatus,
    onVaultDeleted: (message) => onVaultDeleted(message),
  })
  const cleanupState = cleanupController.state
  requestDelete = cleanupController.requestDelete
  requestBulkDelete = cleanupController.requestBulkDelete

  const browserFillController = createBrowserFillController({
    stores: appStores,
    feedback: feedbackController,
    onVaultLocked: () => onNativeVaultLocked(),
    modal: modalController,
    blockingOverlayActive: () => onboardingState.value().step !== 'none',
  })

  const identityFillController = createIdentityFillController({
    stores: appStores,
    feedback: feedbackController,
    onVaultLocked: () => onNativeVaultLocked(),
    modal: modalController,
    blockingOverlayActive: () => onboardingState.value().step !== 'none',
  })

  const cardFillController = createCardFillController({
    stores: appStores,
    feedback: feedbackController,
    onVaultLocked: () => onNativeVaultLocked(),
    modal: modalController,
    blockingOverlayActive: () => onboardingState.value().step !== 'none',
  })

  const browserSaveController = createBrowserSaveController({
    stores: appStores,
    feedback: feedbackController,
    onVaultLocked: () => onNativeVaultLocked(),
    modal: modalController,
    blockingOverlayActive: () => onboardingState.value().step !== 'none',
  })

  const backupController = createBackupController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
    onRestored: (message) => onRestored(message),
  })
  const backupState = backupController.state

  const identityController = createIdentityController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const identityState = identityController.state

  const secureNoteController = createSecureNoteController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const secureNoteState = secureNoteController.state

  const cardController = createCardController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const cardState = cardController.state

  const wifiNetworkController = createWifiNetworkController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const wifiNetworkState = wifiNetworkController.state

  const sshKeyController = createSshKeyController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const sshKeyState = sshKeyController.state

  const softwareLicenseController = createSoftwareLicenseController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const softwareLicenseState = softwareLicenseController.state

  const documentController = createDocumentController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const documentState = documentController.state
  const documentAttachmentState = documentController.attachmentState

  const customRecordController = createCustomRecordController({
    stores: appStores,
    feedback: feedbackController,
    modal: modalController,
  })
  const customRecordState = customRecordController.state

  const trashController = createTrashController({
    stores: appStores,
    feedback: feedbackController,
  })

  const historyController = createHistoryController({
    stores: appStores,
    feedback: feedbackController,
  })
  const trashState = trashController.state
  const historyState = historyController.state

  const itemController = createItemController({
    stores: appStores,
    feedback: feedbackController,
    login: loginController,
    editors: {
      identity: identityController,
      secure_note: secureNoteController,
      card: cardController,
      wifi_network: wifiNetworkController,
      ssh_key: sshKeyController,
      software_license: softwareLicenseController,
      document: documentController,
      custom_record: customRecordController,
    },
  })
  const itemState = itemController.state
  const visibleItems = itemController.visibleItems
  const allItems = itemController.allItems
  const recentItems = itemController.recentItems
  let focusSearchToken = 0

  // Universal search means every item, so it clears the filters first.
  function openUniversalSearch() {
    selection.patch({ activeView: 'vault', categoryFilter: null, collectionFilter: null, securityFilter: null })
    focusSearchToken += 1
  }

  function historyItemTitle(_kind: string, itemId: string): string | null {
    return vaultItems($vault.snapshot).find((item) => item.id === itemId)?.title ?? null
  }

  function clearSessionState() {
    loginController.clearSecrets()
    importController.clearSecrets()
    cleanupController.clearSecrets()
    backupController.clearSecrets()
    settingsController.clearSecrets()
    browserFillController.clearSecrets()
    identityFillController.clearSecrets()
    cardFillController.clearSecrets()
    browserSaveController.clearSecrets()
    identityController.clearSecrets()
    secureNoteController.clearSecrets()
    cardController.clearSecrets()
    wifiNetworkController.clearSecrets()
    sshKeyController.clearSecrets()
    softwareLicenseController.clearSecrets()
    documentController.clearSecrets()
    customRecordController.clearSecrets()
    trashController.clearSecrets()
    historyController.clearSecrets()
    itemController.clearSecrets()
    generator.clear()
    passphrase.clear()
    recentGenerations.clear()
  }

  async function refreshActiveView() {
    if (selection.value().activeView === 'security' && cleanupState.value().duplicateReviewOpen) {
      await cleanupController.loadDuplicateGroups()
    }
    if (selection.value().activeView === 'settings') {
      await Promise.all([
        settingsController.refreshDiagnosticStatus(),
        settingsController.refreshServiceConnection(),
        settingsController.refreshBrowserIntegration(),
        settingsController.refreshWebsiteIconCache(),
      ])
    }
    if (selection.value().activeView === 'authenticator') {
      authenticatorReloadToken += 1
    }
    if (selection.value().activeView === 'backups') {
      await backupController.refreshHealth()
    }
  }

  const unlockController = createUnlockController({
    stores: appStores,
    feedback: feedbackController,
    selectItem: itemController.select,
    clearSelection: itemController.clearSelection,
    clearSessionState,
    rejectBrowserFill: async () => {
      if (browserFill.value().request) await browserFillController.resolve(null)
      if (browserIdentityFill.value().request) await identityFillController.resolve(null)
      if (browserCardFill.value().request) await cardFillController.resolve(null)
      if (browserSave.value().request) await browserSaveController.resolve(false)
    },
    refreshActiveView,
    openPinSetup: settingsController.openPinSetup,
    onboarding: onboardingController,
    modal: modalController,
  })
  const unlockState = unlockController.state
  onVaultDeleted = (message) => {
    settingsController.resetOnboarding()
    unlockController.markVaultDeleted(message)
  }
  onRestored = unlockController.markRestored
  onNativeVaultLocked = () => unlockController.applyLockedUi('Vault locked.')

  $: if ($vault.status.unlocked && $settingsState.preferenceLoaded) {
    onboardingController.startIfNeeded($settingsState.betaOnboardingDismissed, $vault.status.onboardingRequired ?? false)
  }

  const navigation: NavigationGroup[] = [
    { label: 'Workspace', items: [
      { id: 'vault', label: 'Vault', icon: 'vault' },
      { id: 'authenticator', label: 'Authenticator', icon: 'shield' },
      { id: 'security', label: 'Security', icon: 'shield' },
    ] },
    { label: 'Manage', items: [
      { id: 'tools', label: 'Tools', icon: 'key' },
      { id: 'backups', label: 'Backups', icon: 'archive' },
      { id: 'history', label: 'History', icon: 'refresh' },
      { id: 'trash', label: 'Trash', icon: 'trash' },
    ] },
    { label: '', items: [
      { id: 'settings', label: 'Settings', icon: 'settings' },
    ] },
  ]
  const importSources: Array<{ value: ImportSource; label: string }> = [
    { value: 'bitwarden-csv', label: 'Bitwarden CSV' },
    { value: 'bitwarden-json', label: 'Bitwarden JSON' },
    { value: 'dashlane-csv', label: 'Dashlane CSV' },
    { value: 'lastpass-csv', label: 'LastPass CSV' },
    { value: 'onepassword-csv', label: '1Password CSV' },
    { value: 'keepass-csv', label: 'KeePass CSV' },
    { value: 'chrome-csv', label: 'Google Chrome CSV' },
    { value: 'edge-csv', label: 'Microsoft Edge CSV' },
    { value: 'brave-csv', label: 'Brave CSV' },
    { value: 'google-csv', label: 'Google Password Manager CSV' },
    { value: 'apple-csv', label: 'Apple Passwords CSV' },
    { value: 'firefox-csv', label: 'Firefox CSV' },
    { value: 'proton-pass-csv', label: 'Proton Pass CSV' },
    { value: 'keeper-csv', label: 'Keeper CSV' },
    { value: 'nordpass-csv', label: 'NordPass CSV' },
    { value: 'otpauth-txt', label: 'Authenticator app (otpauth links)' },
    { value: 'aegis-json', label: 'Aegis JSON' },
    { value: '2fas-json', label: '2FAS JSON' },
  ]

  onMount(() => {
    let stopQuickAccessOpen = () => {}
    let quickAccessListenerDisposed = false
    void onQuickAccessOpenItem((id) => {
      if (quickAccessListenerDisposed) return
      const item = vaultItems(appStores.vault.value().snapshot).find((candidate) => candidate.id === id)
      if (!item) return
      selection.patch({ activeView: 'vault' })
      void itemController.select(item.id, item.kind)
    })
      .then((stop) => { if (quickAccessListenerDisposed) stop(); else stopQuickAccessOpen = stop })
      .catch(() => void recordDiagnostic('renderer', 'quick_access_listener_failed'))
    const stopSettings = settingsController.start()
    const stopBrowserFill = browserFillController.start()
    const stopIdentityFill = identityFillController.start()
    const stopCardFill = cardFillController.start()
    const stopBrowserSave = browserSaveController.start()
    void loadPlatformCapabilities().catch(() => void recordDiagnostic('renderer', 'platform_capabilities_failed'))
    void unlockController.loadStatus()
    const onRendererError = () => { void recordDiagnostic('renderer', 'unhandled_exception'); void settingsController.refreshDiagnosticStatus() }
    const onUnhandledRejection = () => { void recordDiagnostic('renderer', 'unhandled_rejection'); void settingsController.refreshDiagnosticStatus() }
    window.addEventListener('error', onRendererError)
    window.addEventListener('unhandledrejection', onUnhandledRejection)
    // Failing to subscribe costs the warning, never the lock: Rust decides.
    let stopIdleWarning = () => {}
    let stopIdleCleared = () => {}
    let idleListenersDisposed = false
    void onIdleWarning((secondsLeft) => { if (!idleListenersDisposed) unlockController.showIdleWarning(secondsLeft) })
      .then((stop) => { if (idleListenersDisposed) stop(); else stopIdleWarning = stop })
      .catch(() => void recordDiagnostic('renderer', 'idle_warning_listener_failed'))
    void onIdleWarningCleared(() => { if (!idleListenersDisposed) unlockController.clearIdleWarning() })
      .then((stop) => { if (idleListenersDisposed) stop(); else stopIdleCleared = stop })
      .catch(() => void recordDiagnostic('renderer', 'idle_warning_listener_failed'))
    return () => {
      stopSettings()
      stopBrowserFill()
      stopIdentityFill()
      stopCardFill()
      stopBrowserSave()
      idleListenersDisposed = true
      quickAccessListenerDisposed = true
      stopQuickAccessOpen()
      stopIdleWarning()
      stopIdleCleared()
      window.removeEventListener('error', onRendererError)
      window.removeEventListener('unhandledrejection', onUnhandledRejection)
      clearSessionState()
      unlockController.clearSecrets()
      feedbackController.destroy()
      totp.stop()
    }
  })

  function navigate(view: View) {
    selection.patch({ activeView: view })
    cleanupController.setDuplicateReviewOpen(false)
    if (view === 'settings') {
      void Promise.all([
        settingsController.refreshServiceConnection(),
        settingsController.refreshBrowserIntegration(),
        settingsController.refreshWebsiteIconCache(),
      ])
    }
  }
</script>

<svelte:head>
  <title>Sesame</title>
  <meta name="description" content="Local-first password and recovery vault." />
</svelte:head>

<AppChrome keepInTray={$settings.keepInTray} idleWarningSeconds={$unlockState.idleWarningSeconds} onStayUnlocked={unlockController.clearIdleWarning} preview={$vault.status.preview} />

{#if $unlockState.isWorking && !$vault.status.unlocked}
  <main class="loading-screen" aria-live="polite">
    <div class="loading-mark"><img class="sesame-mark large" src="/favicon.svg" alt="" width="512" height="512" /><span class="loading-spinner" aria-hidden="true"></span></div>
    <p>Opening Sesame…</p>
  </main>
{:else if $vault.status.unlocked && ($onboardingState.step === 'recovery-display' || $onboardingState.step === 'recovery-verify')}
  {#key $onboardingState.step}
    <RecoveryKitScreen
      recoveryKit={$unlockState.recoveryKit}
      bind:recoveryConfirmed={$unlockState.recoveryConfirmed}
      verifyMode={$onboardingState.step === 'recovery-verify'}
      onContinue={$onboardingState.step === 'recovery-verify' ? unlockController.finishRecoveryKit : unlockController.continueRecoveryKitSetup}
      onViewKit={$onboardingState.step === 'recovery-verify' ? () => onboardingController.skipTo('recovery-display') : undefined}
      onSaveToFile={$onboardingState.step === 'recovery-verify' ? undefined : (kit) => exportRecoveryKit(kit)}
    />
  {/key}
{:else if !$vault.status.unlocked && !$vault.status.exists && !setupWelcomeSeen && !$unlockState.restoreMessage}
  <WelcomeScreen
    onStart={() => (setupWelcomeSeen = true)}
    onRestoreBackup={() => void backupController.beginRestore()}
    errorMessage={$feedbackState.errorMessage}
  />
{:else if !$vault.status.unlocked}
  <UnlockScreen
    status={$vault.status}
    bind:recoveryUnlockOpen={$unlockState.recoveryUnlockOpen}
    bind:masterPassword={$unlockState.masterPassword}
    bind:unlockPin={$unlockState.unlockPin}
    bind:confirmPassword={$unlockState.confirmPassword}
    bind:errorMessage={$feedbackState.errorMessage}
    isWorking={$unlockState.isWorking}
    restoreMessage={$unlockState.restoreMessage}
    onUnlockWithPin={unlockController.unlockUsingPin}
    onUnlockWithHello={unlockController.unlockUsingHello}
    onSubmitMasterPassword={unlockController.submitMasterPassword}
  />
{:else}
  <WorkspaceShell
    {navigation}
    preview={$vault.status.preview}
    duplicateReviewOpen={$cleanupState.duplicateReviewOpen}
    notice={$feedbackState.notice}
    errorMessage={$feedbackState.errorMessage}
    onNavigate={navigate}
    onLock={() => unlockController.lock()}
    onDismissNotice={feedbackController.dismissNotice}
    onDismissError={feedbackController.clearError}
    onNewLogin={() => loginController.openNew()}
    onCopyPassword={() => void loginController.copySelectedField('password')}
    onCopyUsername={() => void loginController.copySelectedField('username')}
    onEditSelected={loginController.openEditor}
    onOpenSearch={openUniversalSearch}
  >
    {#if $selection.activeView === 'vault'}
      <VaultView
        allItems={$allItems}
        visibleItems={$visibleItems}
        recentItems={$recentItems}
        itemDetail={$itemState.detail}
        itemLoading={$itemState.loading}
        addMenuOpen={$itemState.addMenuOpen}
        filterMenuOpen={$itemState.filterMenuOpen}
        {focusSearchToken}
        bind:passwordVisible={$loginState.passwordVisible}
        revealedPassword={$loginState.revealedPassword}
        passwordPresenceRequired={$loginState.passwordPresenceRequired}
        bind:passwordPresenceSecret={$loginState.passwordPresenceSecret}
        passwordPresenceError={$loginState.passwordPresenceError}
        onRevealPassword={() => loginController.togglePasswordReveal()}
        onCopyPassword={() => void loginController.copySelectedField('password')}
        onConfirmPasswordPresence={() => void loginController.confirmPasswordPresence()}
        onCancelPasswordPresence={loginController.cancelPasswordPresence}
        siteIconsEnabled={$settings.siteIconsEnabled}
        totpRemaining={$totp.remaining}
        totpProgress={$totp.progress}
        totpRefreshIssue={$totp.refreshIssue}
        multiSelect={$loginState.multiSelect}
        selectedIds={$loginState.selectedIds}
        bulkFolderId={$loginState.bulkFolderId}
        onSelectItem={(id, kind) => void itemController.select(id, kind)}
        onAddItem={itemController.openNew}
        onToggleAddMenu={itemController.toggleAddMenu}
        onToggleFilterMenu={itemController.toggleFilterMenu}
        onOpenNewLogin={loginController.openNew}
        onImport={importController.open}
        onClearSearch={itemController.clearSearch}
        onSearch={(query) => void itemController.runSearch(query)}
        onSetSortMode={(mode) => { if (isSortMode(mode)) { selection.patch({ sortMode: mode }); storeSortMode(mode) } }}
        onClearSecurityFilter={cleanupController.clearSecurityFilter}
        onSetCategory={itemController.setCategory}
        onShowCollection={itemController.showCollection}
        onOrganizeFolders={loginController.openFolderManager}
        onOpenContextMenu={loginController.openEntryMenu}
        onOpenLoginEditor={loginController.openEditor}
        onOpenItemEditor={() => void itemController.openEditor()}
        onDeleteItem={itemController.requestDelete}
        onMoveItem={(folderId) => $selection.activeItemId && void itemController.moveToFolder($selection.activeItemId, folderId)}
        onItemCopy={(value, label) => void itemController.copy(value, label)}
        onOpenRecoveryNotApplicable={loginController.markRecoveryNotApplicable}
        onFixWeakPassword={loginController.openEditorWithFreshPassword}
        recoveryActionWorking={$loginState.recoveryActionWorking}
        breachCheckOpen={$loginState.breachCheckOpen}
        breachCheckWorking={$loginState.breachCheckWorking}
        breachCheckResult={$loginState.breachCheckResult}
        breachCheckError={$loginState.breachCheckError}
        onToggleBreachCheck={loginController.toggleBreachCheck}
        onRunBreachCheck={() => void loginController.runBreachCheck()}
        autoTypeEntryId={$loginState.autoTypeEntryId}
        autoTypeCountdown={$loginState.autoTypeCountdown}
        onStartAutoType={loginController.startAutoType}
        onCancelAutoType={loginController.cancelAutoType}
        onCopy={loginController.copy}
        onOpenWebsite={loginController.openCurrentWebsite}
        onGoSecurity={() => selection.patch({ activeView: 'security' })}
        onAddWebsite={loginController.openEditorWebsite}
        onOpenDuplicateReview={cleanupController.openDuplicateReview}
        onToggleFavourite={(id, favourite) => void itemController.toggleFavourite(id, favourite)}
        onStartMultiSelect={loginController.startMultiSelect}
        onToggleMultiSelect={loginController.toggleMultiSelect}
        onSelectVisible={loginController.selectVisible}
        onSetBulkFolderId={loginController.setBulkFolderId}
        onBulkMove={loginController.bulkMoveSelected}
        onBulkFavourite={() => void loginController.bulkFavouriteSelected()}
        onBulkDelete={loginController.bulkDeleteSelected}
        onCancelMultiSelect={loginController.clearMultiSelect}
      />
    {:else if $selection.activeView === 'security'}
      <CheckupView
        bind:duplicateReviewOpen={$cleanupState.duplicateReviewOpen}
        duplicateReviewLoading={$cleanupState.duplicateReviewLoading}
        duplicateGroups={$cleanupState.duplicateGroups}
        duplicateGroupId={$cleanupState.duplicateGroupId}
        duplicateSelectedIds={$cleanupState.duplicateSelectedIds}
        snapshot={$vault.snapshot}
        onSelectGroup={cleanupController.selectDuplicateGroup}
        onSelectEntry={cleanupController.selectDuplicateEntry}
        onEdit={cleanupController.editCleanupEntry}
        onMerge={cleanupController.requestMerge}
        onDelete={cleanupController.requestDelete}
        onOpenDuplicateReview={cleanupController.openDuplicateReview}
        onShowSecurityFilter={cleanupController.showSecurityFilter}
      />
    {:else if $selection.activeView === 'authenticator'}
      <AuthenticatorView onOpenImport={importController.open} reloadToken={authenticatorReloadToken} />
    {:else if $selection.activeView === 'tools'}
      <ToolsView onCopy={loginController.copy} onUseInLogin={(password) => loginController.openNew(password)} />
    {:else if $selection.activeView === 'trash'}
      <TrashView
        items={$vault.snapshot?.trash ?? []}
        restoringId={$trashState.restoringId}
        previewingId={$trashState.previewingId}
        previewId={$trashState.previewId}
        preview={$trashState.preview}
        onPreview={(id) => void trashController.preview(id)}
        onCancelPreview={trashController.cancelPreview}
        onRestore={(id) => void trashController.restore(id)}
      />
    {:else if $selection.activeView === 'history'}
      <HistoryView
        items={$vault.snapshot?.history ?? []}
        restoringId={$historyState.restoringId}
        previewingId={$historyState.previewingId}
        previewId={$historyState.previewId}
        preview={$historyState.preview}
        onPreview={(id) => void historyController.preview(id)}
        onCancelPreview={historyController.cancelPreview}
        onRestore={(id) => void historyController.restore(id)}
        titleFor={historyItemTitle}
      />
    {:else if $selection.activeView === 'backups'}
      <BackupsView health={$backupState.health} currentRevision={Math.max($vault.snapshot?.revision ?? 0, $vault.status.revision)} exportPresenceRequired={$backupState.exportPresenceRequired} bind:exportPresencePassword={$backupState.exportPresencePassword} errorMessage={$feedbackState.errorMessage} onExportBackup={backupController.exportEncryptedBackup} onConfirmPresence={backupController.confirmExportPresence} onBeginRestore={backupController.beginRestore} onMakeBackup={backupController.makeBackup} onOpenDrill={backupController.openDrill} />
    {:else}
      <SettingsView
        theme={$settings.theme}
        siteIconsEnabled={$settings.siteIconsEnabled}
        autoLockMinutes={$settings.autoLockMinutes}
        {autoLockOptions}
        clipboardClearSeconds={$settings.clipboardClearSeconds}
        {clipboardClearOptions}
        onSetClipboardClearSeconds={settingsController.setClipboardClearSeconds}
        pinUnlockAvailable={$vault.status.pinUnlockAvailable}
        pinWorking={$settingsState.pinWorking}
        onTogglePin={settingsController.togglePinUnlock}
        helloUnlockAvailable={$vault.status.helloUnlockAvailable}
        helloWorking={$settingsState.helloWorking}
        onToggleHello={settingsController.toggleHelloUnlock}
        onChangeMasterPassword={settingsController.openChangeMasterPassword}
        keepInTray={$settings.keepInTray}
        trayWorking={$settingsState.trayWorking}
        onToggleTray={settingsController.toggleTray}
        autostartEnabled={$settingsState.autostartEnabled}
        autostartWorking={$settingsState.autostartWorking}
        onToggleAutostart={settingsController.toggleAutostart}
        quickAccessShortcut={$settings.quickAccessShortcut}
        quickAccessShortcutWorking={$settingsState.quickAccessShortcutWorking}
        onUpdateQuickAccessShortcut={settingsController.updateQuickAccessShortcut}
        onSetTheme={settingsController.setTheme}
        onSetSiteIconsEnabled={settingsController.setSiteIconsEnabled}
        websiteIconCacheWorking={$settingsState.websiteIconCacheWorking}
        websiteIconCacheEntryCount={$settingsState.websiteIconCache.entryCount}
        websiteIconCacheIconCount={$settingsState.websiteIconCache.iconCount}
        websiteIconCacheSizeBytes={$settingsState.websiteIconCache.sizeBytes}
        onClearWebsiteIconCache={settingsController.clearWebsiteIcons}
        onSetAutoLockMinutes={settingsController.setAutoLockMinutes}
        onManageData={cleanupController.openDataControls}
        diagnosticStatus={$settingsState.diagnosticStatus}
        diagnosticEventCount={$settingsState.diagnosticStatus.eventCount}
        diagnosticErrorCount={$settingsState.diagnosticStatus.errorCount}
        diagnosticWorking={$settingsState.diagnosticWorking}
        onExportDiagnostics={settingsController.exportLocalDiagnostics}
        onClearDiagnostics={settingsController.clearLocalDiagnostics}
        serviceConnection={$settingsState.serviceConnection}
        serviceWorking={$settingsState.serviceWorking}
        serviceConnectionAvailable={!previewMode}
        desktopUpdate={$settingsState.updateStatus}
        updateWorking={$settingsState.updateWorking}
        updateProgress={$settingsState.updateProgress}
        onCheckForUpdate={() => settingsController.checkForUpdate(true)}
        onInstallUpdate={settingsController.installUpdate}
        onLinkService={settingsController.connectService}
        onDisconnectService={settingsController.unlinkService}
        onRefreshService={settingsController.refreshServiceConnection}
        browserIntegration={$settingsState.browserIntegration}
        browserIntegrationWorking={$settingsState.browserIntegrationWorking}
        onRefreshBrowserIntegration={() => settingsController.refreshBrowserIntegration(true)}
        onRepairBrowserIntegration={settingsController.repairBrowserIntegration}
        onOpenWebsite={(url) => void openWebsite(url)}
      />
    {/if}
  </WorkspaceShell>
{/if}

  {#if $loginState.entryMenu && $contextEntry}
    <EntryContextMenu
      entry={$contextEntry}
      x={$loginState.entryMenu.x}
      y={$loginState.entryMenu.y}
      folders={$folderOptions}
      working={$loginState.folderWorking}
      onClose={loginController.closeEntryMenu}
      onOpen={() => void loginController.openContextSite($contextEntry.id)}
      onCopyUsername={() => void loginController.copyContextField($contextEntry.id, 'username')}
      onCopyEmail={() => void loginController.copyContextField($contextEntry.id, 'email')}
      onCopyPassword={() => void loginController.copyContextField($contextEntry.id, 'password')}
      onEdit={() => void loginController.editContext($contextEntry.id)}
      onDelete={() => loginController.deleteContext($contextEntry)}
      onMove={(folder) => void loginController.moveContext(folder)}
      onNewFolder={loginController.startNewFolderForContext}
      onToggleFavourite={() => void loginController.toggleContextFavourite($contextEntry.id, !$contextEntry.favourite)}
    />
  {/if}

  {#if $browserFill.request}
    <BrowserFillApprovalModal request={$browserFill.request} working={$browserFill.working} onCancel={() => void browserFillController.resolve(null)} onConfirm={() => void browserFillController.resolve($browserFill.selectedId, $browserFill.remember)} />
  {:else if $browserIdentityFill.request}
    <BrowserIdentityFillApprovalModal request={$browserIdentityFill.request} working={$browserIdentityFill.working} onCancel={() => void identityFillController.resolve(null)} onConfirm={() => void identityFillController.resolve($browserIdentityFill.selectedId)} />
  {:else if $browserCardFill.request}
    <BrowserCardFillApprovalModal request={$browserCardFill.request} working={$browserCardFill.working} onCancel={() => void cardFillController.resolve(null)} onConfirm={() => void cardFillController.resolve($browserCardFill.selectedId)} />
  {:else if $browserSave.request}
    <BrowserSaveApprovalModal request={$browserSave.request} working={$browserSave.working} onCancel={() => void browserSaveController.resolve(false)} onConfirm={() => void browserSaveController.resolve(true)} />
  {/if}

  <ModalHost active={$modalState.active} let:active>
    {#if active?.kind === 'pin-setup'}
      <PinSetupModal
        bind:pin={$settingsState.pinSetupValue}
        bind:confirmPin={$settingsState.pinSetupConfirm}
        errorMessage={$feedbackState.errorMessage}
        working={$settingsState.pinWorking}
        setupStep={$onboardingState.step === 'pin-choice' ? 3 : 0}
        onEdit={feedbackController.clearError}
        onCancel={settingsController.closePinSetup}
        onSave={settingsController.savePin}
      />
    {:else if active?.kind === 'change-master-password'}
      <ChangeMasterPasswordModal
        bind:currentPassword={$settingsState.currentMasterPassword}
        bind:newPassword={$settingsState.newMasterPassword}
        bind:confirmPassword={$settingsState.confirmNewMasterPassword}
        bind:recoveryKit={$settingsState.newRecoveryKit}
        bind:recoveryConfirmed={$settingsState.newRecoveryConfirmed}
        errorMessage={$feedbackState.errorMessage}
        working={$settingsState.changingMasterPassword}
        onCancel={settingsController.cancelChangeMasterPassword}
        onSave={() => void settingsController.saveChangedMasterPassword()}
        onDone={settingsController.finishMasterPasswordChange}
      />
    {:else if active?.kind === 'data-controls'}
      <DataControlsModal
        dataActionWorking={$cleanupState.dataActionWorking}
        bind:readableExportConfirmed={$cleanupState.readableExportConfirmed}
        exportPresenceRequired={$cleanupState.exportPresenceRequired}
        bind:exportPresencePassword={$cleanupState.exportPresencePassword}
        errorMessage={$feedbackState.errorMessage}
        onClose={cleanupController.closeDataControls}
        onExportReadable={cleanupController.exportReadableVault}
        onConfirmPresence={cleanupController.confirmExportPresence}
        onOpenDeleteVault={cleanupController.openDeleteVault}
      />
    {:else if active?.kind === 'delete-vault'}
      <DeleteVaultModal bind:deleteVaultPassword={$cleanupState.deleteVaultPassword} errorMessage={$feedbackState.errorMessage} dataActionWorking={$cleanupState.dataActionWorking} onCancel={cleanupController.closeDeleteVault} onConfirm={cleanupController.confirmDeleteVault} />
    {:else if active?.kind === 'delete-login'}
      <ConfirmDeleteModal deleteCandidate={$cleanupState.deleteCandidate} deleteBatch={$cleanupState.deleteBatch} cleanupWorking={$cleanupState.cleanupWorking} onCancel={cleanupController.cancelDelete} onConfirm={cleanupController.confirmDelete} />
    {:else if active?.kind === 'merge'}
      <ConfirmMergeModal
        mergeCandidate={$cleanupState.mergeCandidate}
        bind:mergeKeepId={$cleanupState.mergeKeepId}
        bind:mergeChoices={$cleanupState.mergeChoices}
        mergeComparison={$cleanupState.mergeComparison}
        cleanupWorking={$cleanupState.cleanupWorking}
        onCancel={cleanupController.cancelMerge}
        onConfirm={cleanupController.confirmMerge}
      />
    {:else if active?.kind === 'import'}
      <ImportModal {importSources} onClose={importController.close} onChooseSource={importController.chooseSource} onHandleImport={importController.chooseFile} onResetImport={importController.reset} onConfirmImport={importController.confirm} />
    {:else if active?.kind === 'restore'}
      <RestoreModal
        restoreSelection={$backupState.restoreSelection}
        bind:restoreConfirmed={$backupState.restoreConfirmed}
        bind:restoreSecret={$backupState.restoreSecret}
        restoringBackup={$backupState.restoringBackup}
        replacesVault={$vault.status.exists}
        errorMessage={$feedbackState.errorMessage}
        onClose={backupController.closeRestore}
        onConfirm={backupController.confirmRestore}
      />
    {:else if active?.kind === 'backup-drill'}
      <BackupDrillModal
        selection={$backupState.drillSelection}
        bind:secret={$backupState.drillSecret}
        verification={$backupState.drillVerification}
        working={$backupState.drillWorking}
        restoring={$backupState.drillRestoring}
        error={$backupState.drillError}
        onChoose={backupController.chooseDrillBackup}
        onVerify={backupController.verifyDrillBackup}
        onRestore={backupController.restoreVerifiedBackup}
        onClose={backupController.closeDrill}
      />
    {:else if active?.kind === 'login-editor'}
      <LoginEditor
        bind:loginDraft={$loginState.loginDraft}
        folderOptions={$folderOptions}
        editorTitle={$loginState.editorTitle}
        savingLogin={$loginState.savingLogin}
        focusUrl={$loginState.editorFocusUrl}
        hasTotp={$loginState.editorHasTotp}
        onSubmit={loginController.submit}
        onClose={loginController.closeEditor}
        onDelete={loginController.requestCurrentDelete}
      />
    {:else if active?.kind === 'identity-editor'}
      <IdentityEditor
        bind:identityDraft={$identityState.draft}
        editorTitle={$identityState.editorTitle}
        savingIdentity={$identityState.saving}
        loadingIdentity={$identityState.loading}
        legacyFields={$identityState.legacyFields}
        onSubmit={identityController.save}
        onClose={identityController.closeEditor}
      />
    {:else if active?.kind === 'delete-identity'}
      <ConfirmDeleteRecordModal
        recordKind="identity"
        noun="identity"
        description="This removes the name, email, phone, and address stored for this identity. It does not touch any saved login."
        deleteCandidate={$identityState.deleteCandidate}
        deleteWorking={$identityState.deleteWorking}
        onCancel={identityController.cancelDelete}
        onConfirm={identityController.confirmDelete}
      />
    {:else if active?.kind === 'secure-note-editor'}
      <SecureNoteEditor
        noteDraft={$secureNoteState.draft}
        editorTitle={$secureNoteState.editorTitle}
        savingNote={$secureNoteState.saving}
        loadingNote={$secureNoteState.loading}
        legacyFields={$secureNoteState.legacyFields}
        onDraftChange={secureNoteController.setDraft}
        onSubmit={secureNoteController.save}
        onClose={secureNoteController.closeEditor}
      />
    {:else if active?.kind === 'delete-secure-note'}
      <ConfirmDeleteRecordModal
        recordKind="secure-note"
        noun="note"
        description="This removes the note and its content from your vault. It does not touch any saved login or identity."
        deleteCandidate={$secureNoteState.deleteCandidate}
        deleteWorking={$secureNoteState.deleteWorking}
        onCancel={secureNoteController.cancelDelete}
        onConfirm={secureNoteController.confirmDelete}
      />
    {:else if active?.kind === 'card-editor'}
      <CardEditor
        bind:cardDraft={$cardState.draft}
        editorTitle={$cardState.editorTitle}
        savingCard={$cardState.saving}
        loadingCard={$cardState.loading}
        legacyFields={$cardState.legacyFields}
        onSubmit={cardController.save}
        onClose={cardController.closeEditor}
      />
    {:else if active?.kind === 'delete-card'}
      <ConfirmDeleteRecordModal
        recordKind="card"
        noun="card"
        description="This removes the card number, expiry, and security code stored for this card. It does not touch any saved login."
        deleteCandidate={$cardState.deleteCandidate}
        deleteWorking={$cardState.deleteWorking}
        onCancel={cardController.cancelDelete}
        onConfirm={cardController.confirmDelete}
      />
    {:else if active?.kind === 'wifi-network-editor'}
      <WifiNetworkEditor
        bind:networkDraft={$wifiNetworkState.draft}
        editorTitle={$wifiNetworkState.editorTitle}
        savingNetwork={$wifiNetworkState.saving}
        loadingNetwork={$wifiNetworkState.loading}
        onSubmit={wifiNetworkController.save}
        onClose={wifiNetworkController.closeEditor}
      />
    {:else if active?.kind === 'delete-wifi-network'}
      <ConfirmDeleteRecordModal
        recordKind="wifi-network"
        noun="network"
        description="This removes the network name and password stored for this network. It does not touch any saved login."
        deleteCandidate={$wifiNetworkState.deleteCandidate}
        deleteWorking={$wifiNetworkState.deleteWorking}
        onCancel={wifiNetworkController.cancelDelete}
        onConfirm={wifiNetworkController.confirmDelete}
      />
    {:else if active?.kind === 'ssh-key-editor'}
      <SshKeyEditor
        bind:keyDraft={$sshKeyState.draft}
        editorTitle={$sshKeyState.editorTitle}
        savingKey={$sshKeyState.saving}
        loadingKey={$sshKeyState.loading}
        onSubmit={sshKeyController.save}
        onClose={sshKeyController.closeEditor}
      />
    {:else if active?.kind === 'delete-ssh-key'}
      <ConfirmDeleteRecordModal
        recordKind="ssh-key"
        noun="key"
        description="This removes the private key, public key, and passphrase stored for this key. It does not touch any saved login."
        deleteCandidate={$sshKeyState.deleteCandidate}
        deleteWorking={$sshKeyState.deleteWorking}
        onCancel={sshKeyController.cancelDelete}
        onConfirm={sshKeyController.confirmDelete}
      />
    {:else if active?.kind === 'software-license-editor'}
      <SoftwareLicenseEditor
        bind:licenseDraft={$softwareLicenseState.draft}
        editorTitle={$softwareLicenseState.editorTitle}
        savingLicense={$softwareLicenseState.saving}
        loadingLicense={$softwareLicenseState.loading}
        onSubmit={softwareLicenseController.save}
        onClose={softwareLicenseController.closeEditor}
      />
    {:else if active?.kind === 'delete-software-license'}
      <ConfirmDeleteRecordModal
        recordKind="software-license"
        noun="licence"
        description="This removes the licence key stored for this licence. It does not touch any saved login."
        deleteCandidate={$softwareLicenseState.deleteCandidate}
        deleteWorking={$softwareLicenseState.deleteWorking}
        onCancel={softwareLicenseController.cancelDelete}
        onConfirm={softwareLicenseController.confirmDelete}
      />
    {:else if active?.kind === 'document-editor'}
      <DocumentEditor
        bind:documentDraft={$documentState.draft}
        editorTitle={$documentState.editorTitle}
        savingDocument={$documentState.saving}
        loadingDocument={$documentState.loading}
        attachments={$documentAttachmentState.documentAttachments}
        uploadingAttachment={$documentAttachmentState.uploadingAttachment}
        removingAttachmentId={$documentAttachmentState.removingAttachmentId}
        attachmentError={$documentAttachmentState.attachmentError}
        onSubmit={documentController.save}
        onClose={documentController.closeEditor}
        onAddAttachment={(file) => void documentController.addAttachment(file)}
        onRemoveAttachment={(attachmentId) => void documentController.removeAttachment(attachmentId)}
      />
    {:else if active?.kind === 'delete-document'}
      <ConfirmDeleteRecordModal
        recordKind="document"
        noun="document"
        description="This removes the document number and other details stored for this document. It does not touch any saved login."
        deleteCandidate={$documentState.deleteCandidate}
        deleteWorking={$documentState.deleteWorking}
        onCancel={documentController.cancelDelete}
        onConfirm={documentController.confirmDelete}
      />
    {:else if active?.kind === 'custom-record-editor'}
      <CustomRecordEditor
        bind:recordDraft={$customRecordState.draft}
        editorTitle={$customRecordState.editorTitle}
        savingRecord={$customRecordState.saving}
        loadingRecord={$customRecordState.loading}
        onSubmit={customRecordController.save}
        onClose={customRecordController.closeEditor}
      />
    {:else if active?.kind === 'delete-custom-record'}
      <ConfirmDeleteRecordModal
        recordKind="custom-record"
        noun="record"
        description="This removes every field stored in this record. It does not touch any saved login."
        deleteCandidate={$customRecordState.deleteCandidate}
        deleteWorking={$customRecordState.deleteWorking}
        onCancel={customRecordController.cancelDelete}
        onConfirm={customRecordController.confirmDelete}
      />
    {:else if active?.kind === 'folder-manager'}
      <FolderManagerModal folders={$folderOptions} entries={$vault.snapshot?.entries ?? []} working={$loginState.folderWorking} onClose={loginController.closeFolderManager} onRename={loginController.startRenameFolder} onUnfile={(folder) => void loginController.unfileFolder(folder)} />
    {:else if active?.kind === 'folder-name'}
      {#if $loginState.folderAction}
        <FolderNameModal
          bind:name={$loginState.folderAction.name}
          title={$loginState.folderAction.kind === 'rename' ? 'Rename folder' : 'New folder'}
          description={$loginState.folderAction.kind === 'rename' ? 'Every login in this folder will move with the new name.' : 'The selected login will move into this folder.'}
          working={$loginState.folderWorking}
          onClose={loginController.closeFolderAction}
          onSave={() => void loginController.confirmFolderAction()}
        />
      {/if}
    {/if}
  </ModalHost>

  {#if $onboardingState.step === 'beta-warning'}
    <BetaOnboarding
      onContinue={() => {
        settingsController.dismissOnboarding()
        onboardingController.dismiss()
      }}
      onOpenBackups={() => {
        settingsController.openBackupsFromOnboarding()
        onboardingController.dismiss()
      }}
    />
  {/if}

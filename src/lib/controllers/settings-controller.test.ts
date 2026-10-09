/* @vitest-environment jsdom */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'
import { createSettingsController } from './settings-controller'

const vaultApi = vi.hoisted(() => ({
  cancelRecoveryReplacement: vi.fn(),
  changeMasterPassword: vi.fn(),
  completeRecoveryReplacement: vi.fn(),
  getRecoveryReplacementStatus: vi.fn(),
  requestRecoveryReplacement: vi.fn(),
  checkDesktopUpdate: vi.fn(),
  clearDiagnostics: vi.fn(),
  clearWebsiteIconCache: vi.fn(),
  disableWindowsHello: vi.fn(),
  disconnectService: vi.fn(),
  downloadAndInstallDesktopUpdate: vi.fn(),
  enableWindowsHello: vi.fn(),
  exportDiagnostics: vi.fn(),
  getAutostartEnabled: vi.fn(),
  getBrowserIntegrationStatus: vi.fn(),
  getDiagnosticStatus: vi.fn(),
  getScreenCaptureAllowed: vi.fn(),
  getServiceConnectionStatus: vi.fn(),
  getVaultStatus: vi.fn(),
  getWebsiteIconCacheStatus: vi.fn(),
  getWebsiteIconsEnabled: vi.fn(),
  grantPresence: vi.fn(),
  linkDesktopService: vi.fn(),
  onDesktopUpdateProgress: vi.fn(),
  recordDiagnostic: vi.fn(),
  removeUnlockPin: vi.fn(),
  repairBrowserIntegration: vi.fn(),
  setAutostartEnabled: vi.fn(),
  setClipboardClearSeconds: vi.fn(),
  setNativeAutoLockMinutes: vi.fn(),
  setQuickAccessShortcut: vi.fn(),
  setScreenCaptureAllowed: vi.fn(),
  setTrayEnabled: vi.fn(),
  setUnlockPin: vi.fn(),
  setWebsiteIconsEnabled: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  PRESENCE_REQUIRED: 'presenceRequired',
  ...vaultApi,
}))

const EMPTY_DIAGNOSTICS = { exists: false, eventCount: 0, errorCount: 0, sizeBytes: 0, localOnly: true, byOperation: [], byCode: [], recent: [] }
const EMPTY_CACHE = { entryCount: 0, iconCount: 0, sizeBytes: 0 }
const EMPTY_SERVICE = { state: 'disconnected', connected: false, online: false, syncAvailable: false, browserHelperAvailable: false }

function harness() {
  const stores = createAppStores()
  const feedback = createFeedbackController()
  const modal = createModalController({ stores, feedback })
  const controller = createSettingsController({ stores, feedback, modal, onPinSetupFinished: vi.fn() })
  return { stores, feedback, controller }
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }),
  })
  vaultApi.getDiagnosticStatus.mockResolvedValue(EMPTY_DIAGNOSTICS)
  vaultApi.getWebsiteIconCacheStatus.mockResolvedValue(EMPTY_CACHE)
  vaultApi.getServiceConnectionStatus.mockResolvedValue(EMPTY_SERVICE)
  vaultApi.getBrowserIntegrationStatus.mockResolvedValue({ ready: true })
  vaultApi.getAutostartEnabled.mockResolvedValue(false)
  vaultApi.getWebsiteIconsEnabled.mockResolvedValue(false)
  vaultApi.getScreenCaptureAllowed.mockResolvedValue(false)
  vaultApi.onDesktopUpdateProgress.mockResolvedValue(() => {})
  vaultApi.recordDiagnostic.mockResolvedValue(undefined)
  vaultApi.setTrayEnabled.mockResolvedValue(undefined)
  vaultApi.setNativeAutoLockMinutes.mockResolvedValue(undefined)
  vaultApi.setQuickAccessShortcut.mockResolvedValue(undefined)
})

describe('website icon opt-in presence', () => {
  it('asks for the master password when an enable is refused', async () => {
    const { stores, controller, feedback } = harness()
    vaultApi.setWebsiteIconsEnabled.mockRejectedValue(new Error('presenceRequired'))

    await controller.setSiteIconsEnabled(true)

    expect(vaultApi.setWebsiteIconsEnabled).toHaveBeenCalledWith(true)
    expect(controller.state.value().siteIconsPresenceRequired).toBe(true)
    expect(stores.settings.value().siteIconsEnabled).toBe(false)
    expect(feedback.state.value().errorMessage).toBe('Confirm your master password before Sesame turns on website icons.')
  })

  it('grants presence and retries the enable once', async () => {
    const { stores, controller } = harness()
    vaultApi.setWebsiteIconsEnabled
      .mockRejectedValueOnce(new Error('presenceRequired'))
      .mockResolvedValueOnce(undefined)
    await controller.setSiteIconsEnabled(true)

    controller.state.patch({ siteIconsPresencePassword: 'fictional master password' })
    vaultApi.grantPresence.mockResolvedValue(undefined)
    await controller.confirmSiteIconsPresence()

    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(vaultApi.setWebsiteIconsEnabled).toHaveBeenCalledTimes(2)
    expect(vaultApi.setWebsiteIconsEnabled).toHaveBeenLastCalledWith(true)
    expect(stores.settings.value().siteIconsEnabled).toBe(true)
    expect(localStorage.getItem('sesame-site-icons')).toBe('enabled')
    expect(controller.state.value()).toMatchObject({ siteIconsPresenceRequired: false, siteIconsPresencePassword: '' })
  })

  it('keeps the prompt open and reports a wrong master password', async () => {
    const { controller, feedback } = harness()
    vaultApi.setWebsiteIconsEnabled.mockRejectedValue(new Error('presenceRequired'))
    await controller.setSiteIconsEnabled(true)
    controller.state.patch({ siteIconsPresencePassword: 'fictional wrong password' })
    vaultApi.grantPresence.mockRejectedValue(new Error('That master password does not open this vault.'))

    await controller.confirmSiteIconsPresence()

    expect(feedback.state.value().errorMessage).toBe('That master password does not open this vault.')
    expect(controller.state.value().siteIconsPresenceRequired).toBe(true)
    expect(vaultApi.setWebsiteIconsEnabled).toHaveBeenCalledTimes(1)
  })

  it('disables without presence', async () => {
    const { stores, controller } = harness()
    stores.settings.patch({ siteIconsEnabled: true })
    vaultApi.setWebsiteIconsEnabled.mockResolvedValue(undefined)

    await controller.setSiteIconsEnabled(false)

    expect(vaultApi.setWebsiteIconsEnabled).toHaveBeenCalledWith(false)
    expect(vaultApi.grantPresence).not.toHaveBeenCalled()
    expect(stores.settings.value().siteIconsEnabled).toBe(false)
    expect(controller.state.value().siteIconsPresenceRequired).toBe(false)
  })
})

describe('website icon opt-in on startup', () => {
  it('turns a stale local preference off instead of enabling without presence', async () => {
    localStorage.setItem('sesame-site-icons', 'enabled')
    const { stores, controller, feedback } = harness()
    vaultApi.getWebsiteIconsEnabled.mockResolvedValue(null)

    controller.start()

    await vi.waitFor(() => expect(stores.settings.value().siteIconsEnabled).toBe(false))
    expect(vaultApi.setWebsiteIconsEnabled).not.toHaveBeenCalled()
    expect(localStorage.getItem('sesame-site-icons')).toBe('disabled')
    expect(feedback.state.value().notice?.title).toBe('Website icons are off')
  })

  it('adopts an already persisted native opt-in', async () => {
    const { stores, controller } = harness()
    vaultApi.getWebsiteIconsEnabled.mockResolvedValue(true)

    controller.start()

    await vi.waitFor(() => expect(stores.settings.value().siteIconsEnabled).toBe(true))
    expect(localStorage.getItem('sesame-site-icons')).toBe('enabled')
    expect(vaultApi.setWebsiteIconsEnabled).not.toHaveBeenCalled()
  })
})

describe('master password change', () => {
  const KIT = 'F9K4P-7XQ2M-T6V8C-H3R5W-J8L2N'

  function openChange() {
    const h = harness()
    h.controller.openChangeMasterPassword()
    return h
  }

  it('checks the current password before it asks for the recovery kit', async () => {
    const { controller, feedback } = openChange()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    controller.state.patch({ currentMasterPassword: 'fictional current password' })

    await controller.verifyCurrentMasterPassword()

    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional current password')
    expect(controller.state.value().changeMasterPasswordStep).toBe('details')
    expect(feedback.state.value().errorMessage).toBe('')
  })

  it('stays on the first step when the current password is wrong', async () => {
    const { controller, feedback } = openChange()
    vaultApi.grantPresence.mockRejectedValue(new Error('That master password is not correct.'))
    controller.state.patch({ currentMasterPassword: 'fictional wrong password' })

    await controller.verifyCurrentMasterPassword()

    expect(controller.state.value().changeMasterPasswordStep).toBe('verify')
    expect(feedback.state.value().errorMessage).toContain('not correct')
  })

  it('sends the current password and the recovery kit with the new password', async () => {
    const { controller } = openChange()
    vaultApi.changeMasterPassword.mockResolvedValue({ recoveryKit: 'FICTI-ONALN-EWKIT-AAAAA-BBBBB', backupsRemaining: 0 })
    vaultApi.getVaultStatus.mockResolvedValue({})
    controller.state.patch({ changeMasterPasswordStep: 'details', currentMasterPassword: 'fictional current password', currentRecoveryKit: ` ${KIT.toLowerCase()} `, newMasterPassword: 'fictional new password', confirmNewMasterPassword: 'fictional new password' })

    await controller.saveChangedMasterPassword()

    expect(vaultApi.changeMasterPassword).toHaveBeenCalledWith('fictional current password', KIT, 'fictional new password')
    expect(controller.state.value().currentRecoveryKit).toBe('')
    expect(controller.state.value().newRecoveryKit).toBe('FICTI-ONALN-EWKIT-AAAAA-BBBBB')
  })

  it('resets a forgotten password with the recovery kit alone', async () => {
    const { controller } = openChange()
    vaultApi.changeMasterPassword.mockResolvedValue({ recoveryKit: 'FICTI-ONALN-EWKIT-AAAAA-BBBBB', backupsRemaining: 0 })
    vaultApi.getVaultStatus.mockResolvedValue({})
    controller.useRecoveryKitForMasterPasswordChange()
    expect(controller.state.value().changeMasterPasswordStep).toBe('details')
    controller.state.patch({ currentRecoveryKit: KIT, newMasterPassword: 'fictional new password', confirmNewMasterPassword: 'fictional new password' })

    await controller.saveChangedMasterPassword()

    expect(vaultApi.grantPresence).not.toHaveBeenCalled()
    expect(vaultApi.changeMasterPassword).toHaveBeenCalledWith(null, KIT, 'fictional new password')
  })

  it('does not send a change without the recovery kit', async () => {
    const { controller, feedback } = openChange()
    controller.state.patch({ changeMasterPasswordStep: 'details', currentMasterPassword: 'fictional current password', currentRecoveryKit: '   ', newMasterPassword: 'fictional new password', confirmNewMasterPassword: 'fictional new password' })

    await controller.saveChangedMasterPassword()

    expect(vaultApi.changeMasterPassword).not.toHaveBeenCalled()
    expect(feedback.state.value().errorMessage).toContain('recovery kit')
  })
})

describe('recovery kit replacement', () => {
  it('requests a new kit only after the master password is confirmed', async () => {
    const { controller } = harness()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.requestRecoveryReplacement.mockResolvedValue({ requestedAt: 1_700_000_000, availableAt: 1_700_259_200, ready: false, timeConfirmed: true })
    controller.startRecoveryKitRequest()
    controller.state.patch({ recoveryPresencePassword: 'fictional master password' })

    await controller.confirmRecoveryPresence()

    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(vaultApi.requestRecoveryReplacement).toHaveBeenCalledTimes(1)
    expect(controller.state.value().recoveryReplacement?.requestedAt).toBe(1_700_000_000)
    expect(controller.state.value().recoveryPresenceIntent).toBeNull()
    expect(controller.state.value().recoveryPresencePassword).toBe('')
  })

  it('does not request a kit when the master password is wrong', async () => {
    const { controller, feedback } = harness()
    vaultApi.grantPresence.mockRejectedValue(new Error('That master password is not correct.'))
    controller.startRecoveryKitRequest()
    controller.state.patch({ recoveryPresencePassword: 'fictional wrong password' })

    await controller.confirmRecoveryPresence()

    expect(vaultApi.requestRecoveryReplacement).not.toHaveBeenCalled()
    expect(controller.state.value().recoveryPresenceIntent).toBe('request-kit')
    expect(feedback.state.value().errorMessage).toContain('not correct')
  })

  it('shows the issued kit and clears it only after it is saved', async () => {
    const { controller } = harness()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.completeRecoveryReplacement.mockResolvedValue('FICTI-ONALN-EWKIT-AAAAA-BBBBB')
    controller.startRecoveryKitIssue()
    controller.state.patch({ recoveryPresencePassword: 'fictional master password' })

    await controller.confirmRecoveryPresence()
    expect(controller.state.value().issuedRecoveryKit).toBe('FICTI-ONALN-EWKIT-AAAAA-BBBBB')

    controller.finishIssuedRecoveryKit()
    expect(controller.state.value().issuedRecoveryKit).toBe('FICTI-ONALN-EWKIT-AAAAA-BBBBB')
    controller.state.patch({ issuedRecoveryConfirmed: true })
    controller.finishIssuedRecoveryKit()
    expect(controller.state.value().issuedRecoveryKit).toBe('')
  })

  it('cancels a pending request without a password', async () => {
    const { controller } = harness()
    vaultApi.cancelRecoveryReplacement.mockResolvedValue(undefined)
    controller.state.patch({ recoveryReplacement: { requestedAt: 1_700_000_000, availableAt: 1_700_259_200, ready: false, timeConfirmed: true } })

    await controller.cancelRecoveryKitRequest()

    expect(vaultApi.grantPresence).not.toHaveBeenCalled()
    expect(controller.state.value().recoveryReplacement?.requestedAt).toBeUndefined()
  })
})

describe('screen capture setting', () => {
  it('starts blocked and reads the stored choice from the desktop app', async () => {
    const { controller } = harness()
    expect(controller.state.value().screenCaptureAllowed).toBe(false)

    vaultApi.getScreenCaptureAllowed.mockResolvedValue(true)
    const stop = controller.start()
    await vi.waitFor(() => expect(controller.state.value().screenCaptureAllowed).toBe(true))
    stop()
  })

  it('stays blocked when the stored choice cannot be read', async () => {
    const { controller } = harness()
    vaultApi.getScreenCaptureAllowed.mockRejectedValue(new Error('unavailable'))

    const stop = controller.start()
    await vi.waitFor(() => expect(vaultApi.getScreenCaptureAllowed).toHaveBeenCalled())

    expect(controller.state.value().screenCaptureAllowed).toBe(false)
    stop()
  })

  it('keeps a toggle made while the first read is still pending', async () => {
    const { controller } = harness()
    let finishRead: (value: boolean) => void = () => {}
    vaultApi.getScreenCaptureAllowed.mockReturnValue(new Promise<boolean>((resolve) => { finishRead = resolve }))
    vaultApi.setScreenCaptureAllowed.mockResolvedValue(undefined)

    const stop = controller.start()
    await vi.waitFor(() => expect(vaultApi.getScreenCaptureAllowed).toHaveBeenCalled())
    await controller.toggleScreenCapture()
    finishRead(false)
    await Promise.resolve()
    await Promise.resolve()

    expect(controller.state.value().screenCaptureAllowed).toBe(true)
    stop()
  })

  it('allows capture only after the desktop app accepts the change', async () => {
    const { controller, feedback } = harness()
    vaultApi.setScreenCaptureAllowed.mockResolvedValue(undefined)

    await controller.toggleScreenCapture()

    expect(vaultApi.setScreenCaptureAllowed).toHaveBeenCalledWith(true)
    expect(controller.state.value()).toMatchObject({ screenCaptureAllowed: true, screenCaptureWorking: false })
    expect(feedback.state.value().notice?.title).toBe('Screen capture allowed')
  })

  it('blocks capture again on the next toggle', async () => {
    const { controller } = harness()
    vaultApi.setScreenCaptureAllowed.mockResolvedValue(undefined)
    await controller.toggleScreenCapture()

    await controller.toggleScreenCapture()

    expect(vaultApi.setScreenCaptureAllowed).toHaveBeenLastCalledWith(false)
    expect(controller.state.value().screenCaptureAllowed).toBe(false)
  })

  it('keeps capture blocked and shows the error when the desktop app refuses', async () => {
    const { controller, feedback } = harness()
    vaultApi.setScreenCaptureAllowed.mockRejectedValue(new Error('Sesame could not save the desktop setting.'))

    await controller.toggleScreenCapture()

    expect(controller.state.value()).toMatchObject({ screenCaptureAllowed: false, screenCaptureWorking: false })
    expect(feedback.state.value().errorMessage).toBe('Sesame could not save the desktop setting.')
  })

  it('ignores a second toggle while the first is still running', async () => {
    const { controller } = harness()
    let finish: () => void = () => {}
    vaultApi.setScreenCaptureAllowed.mockReturnValue(new Promise<void>((resolve) => { finish = resolve }))

    const first = controller.toggleScreenCapture()
    await controller.toggleScreenCapture()
    finish()
    await first

    expect(vaultApi.setScreenCaptureAllowed).toHaveBeenCalledTimes(1)
  })
})

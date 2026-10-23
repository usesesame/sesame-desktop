/* @vitest-environment jsdom */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ServiceConnectionStatus } from '../types'
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
  inspectCustomServer: vi.fn(),
  linkCustomServer: vi.fn(),
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
    vaultApi.getVaultStatus.mockResolvedValue({ exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false })
    vaultApi.completeRecoveryReplacement.mockResolvedValue({ recoveryKit: 'FICTI-ONALN-EWKIT-AAAAA-BBBBB' })
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

  it('sends the master password with the issue request and keeps backups unless asked', async () => {
    const { controller } = harness()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.getVaultStatus.mockResolvedValue({ exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false })
    vaultApi.completeRecoveryReplacement.mockResolvedValue({ recoveryKit: 'FICTI-ONALN-EWKIT-AAAAA-BBBBB' })
    controller.startRecoveryKitIssue()
    controller.state.patch({ recoveryPresencePassword: 'fictional master password' })

    await controller.confirmRecoveryPresence()

    expect(vaultApi.completeRecoveryReplacement).toHaveBeenCalledWith('fictional master password', false)
    expect(controller.state.value().issuedBackupsPruned).toBe(false)
    expect(controller.state.value().recoveryPresencePassword).toBe('')
  })

  it('asks the core to delete local backups when the box is checked and reports what remains', async () => {
    const { controller } = harness()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.getVaultStatus.mockResolvedValue({ exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false })
    vaultApi.completeRecoveryReplacement.mockResolvedValue({ recoveryKit: 'FICTI-ONALN-EWKIT-AAAAA-BBBBB', backupsRemaining: 2 })
    controller.startRecoveryKitIssue()
    controller.state.patch({ recoveryPresencePassword: 'fictional master password', recoveryPruneBackups: true })

    await controller.confirmRecoveryPresence()

    expect(vaultApi.completeRecoveryReplacement).toHaveBeenCalledWith('fictional master password', true)
    expect(controller.state.value().issuedBackupsPruned).toBe(true)
    expect(controller.state.value().issuedBackupsRemaining).toBe(2)
    expect(controller.state.value().recoveryPruneBackups).toBe(false)
  })

  it('keeps the issued kit on screen when the status refresh fails afterwards', async () => {
    const { controller, feedback } = harness()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.getVaultStatus.mockRejectedValue(new Error('status unavailable'))
    vaultApi.completeRecoveryReplacement.mockResolvedValue({ recoveryKit: 'FICTI-ONALN-EWKIT-AAAAA-BBBBB' })
    controller.startRecoveryKitIssue()
    controller.state.patch({ recoveryPresencePassword: 'fictional master password' })

    await controller.confirmRecoveryPresence()

    expect(controller.state.value().issuedRecoveryKit).toBe('FICTI-ONALN-EWKIT-AAAAA-BBBBB')
    expect(feedback.state.value().errorMessage).toBe('')
  })

  it('shows no kit when the core refuses the master password', async () => {
    const { controller, feedback } = harness()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.completeRecoveryReplacement.mockRejectedValue(new Error('Your current master password is not correct.'))
    controller.startRecoveryKitIssue()
    controller.state.patch({ recoveryPresencePassword: 'fictional wrong password' })

    await controller.confirmRecoveryPresence()

    expect(controller.state.value().issuedRecoveryKit).toBe('')
    expect(controller.state.value().recoveryPresenceIntent).toBe('issue-kit')
    expect(feedback.state.value().errorMessage).toContain('not correct')
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

    expect(controller.state.value()).toMatchObject({ screenCaptureAllowed: false, screenCaptureKnown: false })
    stop()
  })

  it('keeps the first read when a toggle made while it was pending is refused', async () => {
    const { controller } = harness()
    let finishRead: (value: boolean) => void = () => {}
    vaultApi.getScreenCaptureAllowed.mockReturnValue(new Promise<boolean>((resolve) => { finishRead = resolve }))
    vaultApi.setScreenCaptureAllowed.mockRejectedValue(new Error('Sesame could not save the desktop setting.'))

    const stop = controller.start()
    await vi.waitFor(() => expect(vaultApi.getScreenCaptureAllowed).toHaveBeenCalled())
    await controller.toggleScreenCapture()
    finishRead(true)

    await vi.waitFor(() => expect(controller.state.value()).toMatchObject({ screenCaptureAllowed: true, screenCaptureKnown: true }))
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

describe('own server pairing', () => {
  const INSPECTION = { address: 'https://sesame.example.test', name: 'Home server', version: '1.0.0', fingerprint: 'a'.repeat(64), fingerprintInLink: true, codeInLink: true, plainHttp: false }
  const CONNECTED = { state: 'connected', connected: true, online: true, deviceName: 'Linux desktop', syncAvailable: false, browserHelperAvailable: false, serverAddress: 'https://sesame.example.test', serverFingerprint: 'a'.repeat(64) }

  it('returns the inspection without changing the stored connection', async () => {
    const { controller } = harness()
    vaultApi.inspectCustomServer.mockResolvedValue(INSPECTION)

    const inspection = await controller.inspectServer('https://sesame.example.test/pair#code=x')

    expect(inspection).toEqual(INSPECTION)
    expect(vaultApi.inspectCustomServer).toHaveBeenCalledWith('https://sesame.example.test/pair#code=x')
    expect(vaultApi.linkCustomServer).not.toHaveBeenCalled()
    expect(controller.state.value().serviceConnection).toEqual(EMPTY_SERVICE)
    expect(controller.state.value().serviceWorking).toBe(false)
  })

  it('reports a refused server and returns nothing to confirm', async () => {
    const { controller, feedback } = harness()
    vaultApi.inspectCustomServer.mockRejectedValue(new Error('The server\'s fingerprint does not match the pairing link. Do not pair with this server.'))

    expect(await controller.inspectServer('https://sesame.example.test')).toBeNull()

    expect(feedback.state.value().errorMessage).toContain('does not match the pairing link')
    expect(controller.state.value().serviceWorking).toBe(false)
  })

  it('sends the confirmed fingerprint with the pairing and stores the result', async () => {
    const { controller, feedback } = harness()
    vaultApi.linkCustomServer.mockResolvedValue(CONNECTED)

    const paired = await controller.connectServer('https://sesame.example.test/pair#code=x', '', INSPECTION.fingerprint)

    expect(paired).toBe(true)
    expect(vaultApi.linkCustomServer).toHaveBeenCalledWith('https://sesame.example.test/pair#code=x', '', INSPECTION.fingerprint)
    expect(controller.state.value().serviceConnection).toEqual(CONNECTED)
    expect(feedback.state.value().notice?.title).toBe('Server connected')
  })

  it('keeps the disconnected state when the pairing is refused', async () => {
    const { controller, feedback } = harness()
    vaultApi.linkCustomServer.mockRejectedValue(new Error('That desktop code is invalid, expired, or has already been used.'))

    expect(await controller.connectServer('https://sesame.example.test', 'x', INSPECTION.fingerprint)).toBe(false)

    expect(controller.state.value().serviceConnection).toEqual(EMPTY_SERVICE)
    expect(feedback.state.value().errorMessage).toBe('That desktop code is invalid, expired, or has already been used.')
    expect(feedback.state.value().notice).toBeNull()
    expect(controller.state.value().serviceWorking).toBe(false)
  })

  it('clears an earlier error before it checks again', async () => {
    const { controller, feedback } = harness()
    feedback.setErrorMessage('An old error')
    vaultApi.inspectCustomServer.mockResolvedValue(INSPECTION)

    await controller.inspectServer('https://sesame.example.test')

    expect(feedback.state.value().errorMessage).toBe('')
  })
})

describe('disconnecting', () => {
  const CONNECTED: ServiceConnectionStatus = { state: 'connected', connected: true, online: true, deviceName: 'Linux desktop', syncAvailable: false, browserHelperAvailable: false }
  const OWN: ServiceConnectionStatus = { ...CONNECTED, serverAddress: 'https://sesame.example.test', serverFingerprint: 'a'.repeat(64) }

  it('says the device is gone from the server when the revocation was sent', async () => {
    const { controller, feedback } = harness()
    controller.state.patch({ serviceConnection: OWN })
    vaultApi.disconnectService.mockResolvedValue({ revokedOnServer: true })

    await controller.unlinkService()

    expect(controller.state.value().serviceConnection).toEqual(EMPTY_SERVICE)
    expect(feedback.state.value().notice?.title).toBe('Desktop disconnected')
    expect(feedback.state.value().notice?.message).not.toMatch(/still be linked/)
    expect(feedback.state.value().errorMessage).toBe('')
  })

  it('warns that an own server may still list the device when the revocation was not sent', async () => {
    const { controller, feedback } = harness()
    controller.state.patch({ serviceConnection: OWN })
    vaultApi.disconnectService.mockResolvedValue({ revokedOnServer: false })

    await controller.unlinkService()

    expect(controller.state.value().serviceConnection).toEqual(EMPTY_SERVICE)
    expect(feedback.state.value().errorMessage).toMatch(/may still be linked on the server/)
    expect(feedback.state.value().errorMessage).toMatch(/server console/)
  })

  it('points an account link at the account when the revocation was not sent', async () => {
    const { controller, feedback } = harness()
    controller.state.patch({ serviceConnection: CONNECTED })
    vaultApi.disconnectService.mockResolvedValue({ revokedOnServer: false })

    await controller.unlinkService()

    expect(feedback.state.value().errorMessage).toMatch(/may still be linked on the server/)
    expect(feedback.state.value().errorMessage).toMatch(/account/)
    expect(feedback.state.value().errorMessage).not.toMatch(/server console/)
  })

  it('keeps the connection on screen when the local removal fails', async () => {
    const { controller, feedback } = harness()
    controller.state.patch({ serviceConnection: OWN })
    vaultApi.disconnectService.mockRejectedValue(new Error('Sesame could not remove the desktop account connection.'))

    await controller.unlinkService()

    expect(controller.state.value().serviceConnection).toEqual(OWN)
    expect(feedback.state.value().errorMessage).toBe('Sesame could not remove the desktop account connection.')
  })
})

describe('the first run Sync notice', () => {
  it('stays hidden until the saved preference has been read, then shows for a device that never saw it', () => {
    const { controller } = harness()
    expect(controller.state.value().syncNoticeSeen).toBe(true)
    expect(localStorage.getItem('sesame-sync-notice-v1')).toBeNull()
  })

  it('remembers that it was seen so it is not shown twice', () => {
    const { controller } = harness()
    controller.state.patch({ syncNoticeSeen: false })
    controller.dismissSyncNotice()
    expect(controller.state.value().syncNoticeSeen).toBe(true)
    expect(localStorage.getItem('sesame-sync-notice-v1')).toBe('seen')
  })

  it('opens the Connections tab and counts as seen when the person asks for Sync settings', () => {
    const { controller } = harness()
    controller.state.patch({ syncNoticeSeen: false, settingsTab: 'general' })
    controller.openSyncSettings()
    expect(controller.state.value().settingsTab).toBe('connections')
    expect(controller.state.value().syncNoticeSeen).toBe(true)
    expect(localStorage.getItem('sesame-sync-notice-v1')).toBe('seen')
  })

  it('shows again after onboarding is reset', () => {
    const { controller } = harness()
    controller.dismissSyncNotice()
    controller.resetOnboarding()
    expect(controller.state.value().syncNoticeSeen).toBe(false)
    expect(localStorage.getItem('sesame-sync-notice-v1')).toBeNull()
  })
})

describe('the manual update check', () => {
  it('claims the latest version only when nothing contradicts it', async () => {
    const { controller, feedback } = harness()
    vaultApi.checkDesktopUpdate.mockResolvedValue({ available: false })
    await controller.checkForUpdate(true)
    expect(feedback.state.value().notice).toMatchObject({ title: 'No update available', message: 'You are running the latest version of Sesame.' })
  })

  it('says it could not confirm updates when the freshness check is stale', async () => {
    const { controller, feedback } = harness()
    vaultApi.checkDesktopUpdate.mockResolvedValue({ available: false, freshness: { state: 'unconfirmed' } })
    await controller.checkForUpdate(true)
    const notice = feedback.state.value().notice
    expect(notice?.title).toBe('Could not confirm updates')
    expect(notice?.message).not.toContain('latest version')
  })

  it('says a newer release exists when the update information is frozen', async () => {
    const { controller, feedback } = harness()
    vaultApi.checkDesktopUpdate.mockResolvedValue({ available: false, freshness: { state: 'newer_exists', version: '0.4.9' } })
    await controller.checkForUpdate(true)
    expect(feedback.state.value().notice?.title).toBe('A newer Sesame exists')
  })
})

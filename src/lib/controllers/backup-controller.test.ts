import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import { PRESENCE_REQUIRED } from '../vault'
import { createBackupController } from './backup-controller'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  chooseBackupForRestore: vi.fn(),
  createBackup: vi.fn(),
  exportBackup: vi.fn(),
  getRecoveryHealth: vi.fn(),
  getVaultStatus: vi.fn(),
  grantPresence: vi.fn(),
  recordDiagnostic: vi.fn(),
  restoreBackup: vi.fn(),
  verifyBackup: vi.fn(),
}))

vi.mock('../vault', () => ({
  PRESENCE_REQUIRED: 'presenceRequired',
  refreshTotp: vi.fn(),
  ...vaultApi,
}))

const STATUS = { exists: true, unlocked: false, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 0 }

function selection(compatibility: 'current' | 'upgrade') {
  return { token: 'fictional-backup-token', fileName: 'fictional-backup.sesame', formatVersion: compatibility === 'current' ? 10 : 8, compatibility, setupComplete: true }
}

function restoredResult(overrides: Record<string, unknown> = {}) {
  return { safetyBackupName: 'sesame-before-restore-1-a.sesame', pinUnlockAvailable: false, helloUnlockAvailable: false, restoredRevision: 2, replacedRevision: 1, ...overrides }
}

function verification() {
  return { ...selection('current'), vaultName: 'Fictional vault', entryCount: 2, vaultId: 'fictional-vault', revision: 2 }
}

function harness() {
  const stores = createAppStores()
  stores.vault.patch({ status: STATUS })
  const feedback = createFeedbackController()
  const modal = createModalController({ stores, feedback })
  const restored: string[] = []
  const controller = createBackupController({ stores, feedback, modal, onRestored: (message) => restored.push(message) })
  return { stores, feedback, controller, restored }
}

async function restoreWith(compatibility: 'current' | 'upgrade') {
  const running = harness()
  vaultApi.getVaultStatus.mockResolvedValue(STATUS)
  vaultApi.recordDiagnostic.mockResolvedValue(undefined)
  vaultApi.chooseBackupForRestore.mockResolvedValue(selection(compatibility))
  await running.controller.beginRestore()
  running.controller.state.patch({ restoreSecret: 'fictional master password 01', restoreConfirmed: true })
  return running
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('backup restore messages', () => {
  it('names the safety backup and the revision delta when a current backup is restored', async () => {
    const running = await restoreWith('current')
    vaultApi.restoreBackup.mockResolvedValue(restoredResult())
    await running.controller.confirmRestore()
    expect(running.restored).toEqual(['Backup restored. Sesame kept the previous vault as sesame-before-restore-1-a.sesame. The restored vault is at revision 2, replacing revision 1.'])
  })

  it('says an older backup was upgraded and names the safety backup', async () => {
    const running = await restoreWith('upgrade')
    vaultApi.restoreBackup.mockResolvedValue(restoredResult({ safetyBackupName: 'sesame-before-restore-2-b.sesame' }))
    await running.controller.confirmRestore()
    expect(running.restored).toEqual(['Older backup upgraded and restored. Sesame kept the previous vault as sesame-before-restore-2-b.sesame. The restored vault is at revision 2, replacing revision 1.'])
  })

  it('omits the revision delta when there was no vault to replace', async () => {
    const running = harness()
    running.stores.vault.patch({ status: { ...STATUS, exists: false } })
    vaultApi.getVaultStatus.mockResolvedValue({ ...STATUS, exists: false })
    vaultApi.chooseBackupForRestore.mockResolvedValue(selection('current'))
    await running.controller.beginRestore()
    running.controller.state.patch({ restoreSecret: 'fictional master password 01', restoreConfirmed: true })
    vaultApi.restoreBackup.mockResolvedValue(restoredResult({ safetyBackupName: undefined, replacedRevision: undefined }))
    await running.controller.confirmRestore()
    expect(running.restored).toEqual(['Backup restored. Unlock with the master password or recovery kit from that backup.'])
  })

  it('asks for the current master password before retrying a restore', async () => {
    const running = await restoreWith('current')
    vaultApi.restoreBackup.mockRejectedValueOnce(new Error(PRESENCE_REQUIRED)).mockResolvedValueOnce(restoredResult({ safetyBackupName: undefined }))
    await running.controller.confirmRestore()
    expect(running.controller.state.value().restorePresenceRequired).toBe(true)
    expect(running.feedback.state.value().errorMessage).toBe('Confirm your current master password before Sesame replaces the vault.')

    running.controller.state.patch({ restorePresencePassword: 'fictional master password 01' })
    vaultApi.grantPresence.mockResolvedValue(undefined)
    await running.controller.confirmRestorePresence()
    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password 01')
    expect(running.controller.state.value().restorePresenceRequired).toBe(false)
    expect(running.restored).toEqual(['Backup restored. The restored vault is at revision 2, replacing revision 1.'])
  })

  it('reports a failed migration with the exact next action and leaves the vault in place', async () => {
    const running = await restoreWith('upgrade')
    const migrationFailure = 'Sesame authenticated vault format 8, but could not upgrade it because its folders are invalid. Keep the original backup and contact support.'
    vaultApi.restoreBackup.mockRejectedValue(new Error(migrationFailure))
    await running.controller.confirmRestore()
    expect(running.feedback.state.value().errorMessage).toBe(migrationFailure)
    expect(running.restored).toEqual([])
    expect(running.controller.state.value().restoringBackup).toBe(false)
  })
})

describe('backup drill restore', () => {
  it('asks for the current master password before retrying a drill restore', async () => {
    const running = harness()
    running.controller.openDrill()
    vaultApi.chooseBackupForRestore.mockResolvedValue(selection('current'))
    await running.controller.chooseDrillBackup()
    vaultApi.verifyBackup.mockResolvedValue(verification())
    running.controller.state.patch({ drillSecret: 'fictional master password 01' })
    await running.controller.verifyDrillBackup()

    vaultApi.restoreBackup.mockRejectedValueOnce(new Error(PRESENCE_REQUIRED))
    await running.controller.restoreVerifiedBackup()
    expect(running.controller.state.value().drillPresenceRequired).toBe(true)

    running.controller.state.patch({ drillPresencePassword: 'fictional master password 01' })
    vaultApi.grantPresence.mockResolvedValue(undefined)
    vaultApi.restoreBackup.mockResolvedValue(restoredResult({ safetyBackupName: undefined }))
    await running.controller.confirmDrillPresence()
    expect(running.controller.state.value().drillError).toBe('')
    expect(running.restored).toEqual(['Recovery drill complete. The verified backup was restored. The restored vault is at revision 2, replacing revision 1.'])
  })
})

describe('backup drill failures', () => {
  async function verifyFailure(message: string) {
    const running = harness()
    vaultApi.chooseBackupForRestore.mockResolvedValue(selection('current'))
    await running.controller.chooseDrillBackup()
    running.controller.state.patch({ drillSecret: 'fictional wrong password' })
    vaultApi.verifyBackup.mockRejectedValue(new Error(message))
    await running.controller.verifyDrillBackup()
    return running
  }

  it('carries the wrong-secret message into the drill error', async () => {
    const running = await verifyFailure('That master password or recovery kit does not open this backup.')
    expect(running.controller.state.value().drillError).toBe('That master password or recovery kit does not open this backup.')
    expect(running.controller.state.value().drillVerification).toBeNull()
  })

  it('carries the integrity-failure message into the drill error', async () => {
    const running = await verifyFailure('The vault data could not be authenticated. Restore a known-good encrypted backup.')
    expect(running.controller.state.value().drillError).toBe('The vault data could not be authenticated. Restore a known-good encrypted backup.')
  })
})

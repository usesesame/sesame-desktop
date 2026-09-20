import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
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
  return { source: '/tmp/fictional-backup.sesame', fileName: 'fictional-backup.sesame', formatVersion: compatibility === 'current' ? 10 : 8, compatibility, setupComplete: true }
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
  it('names the safety backup when a current backup is restored', async () => {
    const running = await restoreWith('current')
    vaultApi.restoreBackup.mockResolvedValue({ safetyBackupName: 'sesame-before-restore-1-a.sesame', pinUnlockAvailable: false, helloUnlockAvailable: false })
    await running.controller.confirmRestore()
    expect(running.restored).toEqual(['Backup restored. Sesame kept the previous vault as sesame-before-restore-1-a.sesame.'])
  })

  it('says an older backup was upgraded and names the safety backup', async () => {
    const running = await restoreWith('upgrade')
    vaultApi.restoreBackup.mockResolvedValue({ safetyBackupName: 'sesame-before-restore-2-b.sesame', pinUnlockAvailable: false, helloUnlockAvailable: false })
    await running.controller.confirmRestore()
    expect(running.restored).toEqual(['Older backup upgraded and restored. Sesame kept the previous vault as sesame-before-restore-2-b.sesame.'])
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

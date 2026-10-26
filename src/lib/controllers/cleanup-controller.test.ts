import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import { createCleanupController } from './cleanup-controller'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  cancelLoginBreachScan: vi.fn(),
  exportVaultCsv: vi.fn(),
  exportVaultJson: vi.fn(),
  grantPresence: vi.fn(),
  recordDiagnostic: vi.fn(),
}))

vi.mock('../vault', () => ({ PRESENCE_REQUIRED: 'presenceRequired', ...vaultApi }))

function harness() {
  const stores = createAppStores()
  const feedback = createFeedbackController()
  const modal = createModalController({ stores, feedback })
  const controller = createCleanupController({
    stores,
    feedback,
    modal,
    selectEntry: vi.fn(),
    editEntry: vi.fn(),
    clearLoginSelection: vi.fn(),
    refreshDiagnostics: vi.fn(),
    onVaultDeleted: vi.fn(),
  })
  return { controller, feedback }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('the complete export', () => {
  it('does nothing until the person confirms that the file is not encrypted', async () => {
    const { controller } = harness()
    await controller.exportCompleteVault()
    expect(vaultApi.exportVaultJson).not.toHaveBeenCalled()
  })

  it('tells the person which file holds every item kind and that it is not encrypted', async () => {
    const { controller, feedback } = harness()
    vaultApi.exportVaultJson.mockResolvedValue('sesame-vault-export-2026-10-22.json')
    controller.setCompleteExportConfirmed(true)
    await controller.exportCompleteVault()
    expect(vaultApi.exportVaultJson).toHaveBeenCalledTimes(1)
    const notice = feedback.state.value().notice
    expect(notice?.title).toBe('Complete export created')
    expect(notice?.message).toContain('sesame-vault-export-2026-10-22.json')
    expect(notice?.message).toContain('not encrypted')
  })

  it('says nothing when the person cancels the file dialog', async () => {
    const { controller, feedback } = harness()
    vaultApi.exportVaultJson.mockResolvedValue(null)
    controller.setCompleteExportConfirmed(true)
    await controller.exportCompleteVault()
    expect(feedback.state.value().notice).toBeNull()
  })

  it('asks for the master password and then repeats the complete export, not the CSV one', async () => {
    const { controller } = harness()
    vaultApi.exportVaultJson.mockRejectedValueOnce(new Error('presenceRequired')).mockResolvedValueOnce('sesame-vault-export.json')
    controller.setCompleteExportConfirmed(true)
    await controller.exportCompleteVault()
    expect(controller.state.value().exportPresenceRequired).toBe(true)

    vaultApi.grantPresence.mockResolvedValue(undefined)
    controller.state.patch({ exportPresencePassword: 'fictional master password 01' })
    await controller.confirmExportPresence()
    expect(vaultApi.grantPresence).toHaveBeenCalledWith('fictional master password 01')
    expect(vaultApi.exportVaultJson).toHaveBeenCalledTimes(2)
    expect(vaultApi.exportVaultCsv).not.toHaveBeenCalled()
  })

  it('still repeats the CSV export after a presence prompt that started there', async () => {
    const { controller } = harness()
    vaultApi.exportVaultCsv.mockRejectedValueOnce(new Error('presenceRequired')).mockResolvedValueOnce(['sesame-vault-export.csv'])
    controller.setReadableExportConfirmed(true)
    await controller.exportReadableVault()
    vaultApi.grantPresence.mockResolvedValue(undefined)
    controller.state.patch({ exportPresencePassword: 'fictional master password 01' })
    await controller.confirmExportPresence()
    expect(vaultApi.exportVaultCsv).toHaveBeenCalledTimes(2)
    expect(vaultApi.exportVaultJson).not.toHaveBeenCalled()
  })
})

describe('cancelling a breach check', () => {
  it('says so when the cancel did not go through, and keeps the scan running', async () => {
    const { controller } = harness()
    controller.state.patch({ breachScan: { phase: 'running', checked: 1, total: 4, results: [] } })
    vaultApi.cancelLoginBreachScan.mockRejectedValue(new Error('no'))
    await controller.cancelBreachScan()
    expect(controller.state.value().breachScanError).toBe('Sesame could not cancel the breach check. It is still running.')
    expect(controller.state.value().breachScan?.phase).toBe('running')
  })
})

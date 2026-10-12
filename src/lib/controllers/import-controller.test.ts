/* @vitest-environment jsdom */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import type { ImportPreview } from '../types'
import { createFeedbackController } from './feedback-controller'
import { createImportController } from './import-controller'
import { createModalController } from './modal-controller'

const vaultApi = vi.hoisted(() => ({
  cancelImport: vi.fn(),
  chooseImportFile: vi.fn(),
  commitImport: vi.fn(),
  previewImportFile: vi.fn(),
  recordDiagnostic: vi.fn(),
  refreshTotp: vi.fn(),
}))

vi.mock('../vault', () => ({ ...vaultApi }))

function preview(overrides: Partial<ImportPreview> = {}): ImportPreview {
  return {
    totalEntries: 2,
    exactDuplicates: 0,
    accountConflicts: 0,
    duplicateEntries: 0,
    missingUrls: 0,
    invalidUrls: 0,
    noTotp: 0,
    invalidTotp: 0,
    preservedLegacyFields: 0,
    secureNotes: 0,
    cards: 0,
    identities: 0,
    sshKeys: 0,
    passkeysNotImported: 0,
    intentionallyOmittedItems: 0,
    fidelity: {
      logins: { imported: 2, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      secureNotes: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      cards: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      identities: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      sshKeys: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      passkeys: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      unsupportedItems: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
    },
    ...overrides,
  }
}

function harness() {
  const stores = createAppStores()
  const feedback = createFeedbackController()
  const modal = createModalController({ stores, feedback })
  const controller = createImportController({
    stores,
    feedback,
    modal,
    refreshDiagnostics: vi.fn(),
    selectEntry: vi.fn(),
  })
  return { stores, feedback, modal, controller }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('malformed or unreadable export files', () => {
  it('reports a file that cannot be read and leaves no preview behind', async () => {
    const running = harness()
    vaultApi.chooseImportFile.mockRejectedValue(new Error('Sesame could not read that file. Keep it and try another copy.'))

    await running.controller.chooseFile()

    expect(running.feedback.state.value().errorMessage).toBe('Sesame could not read that file. Keep it and try another copy.')
    expect(running.stores.imports.value()).toMatchObject({ importing: false, preview: null, importId: '', fileName: '' })
    expect(vaultApi.recordDiagnostic).not.toHaveBeenCalled()
  })

  it('reports a malformed export, records it and never opens a preview', async () => {
    const running = harness()
    vaultApi.chooseImportFile.mockResolvedValue({ token: 'fictional-token', fileName: 'fictional-export.csv' })
    vaultApi.previewImportFile.mockRejectedValue(new Error('This file does not look like a Bitwarden CSV export.'))

    await running.controller.chooseFile()

    expect(running.feedback.state.value().errorMessage).toBe('This file does not look like a Bitwarden CSV export.')
    expect(vaultApi.recordDiagnostic).toHaveBeenCalledWith('import_preview', 'invalid_file')
    expect(running.stores.imports.value()).toMatchObject({ importing: false, preview: null, importId: '', fileName: '' })
  })

  it('leaves everything untouched when the file picker is cancelled', async () => {
    const running = harness()
    vaultApi.chooseImportFile.mockResolvedValue(null)

    await running.controller.chooseFile()

    expect(running.feedback.state.value().errorMessage).toBe('')
    expect(running.stores.imports.value()).toMatchObject({ importing: false, preview: null, importId: '' })
  })
})

describe('keeping a preview honest', () => {
  it('drops a parsed preview when the source changes', async () => {
    const running = harness()
    vaultApi.chooseImportFile.mockResolvedValue({ token: 'fictional-token', fileName: 'fictional-export.csv' })
    vaultApi.previewImportFile.mockResolvedValue({ importId: 'fictional-import', preview: preview() })

    await running.controller.chooseFile()
    expect(running.stores.imports.value()).toMatchObject({ preview: preview(), fileName: 'fictional-export.csv', importId: 'fictional-import' })

    running.controller.chooseSource('lastpass-csv')

    expect(vaultApi.cancelImport).toHaveBeenCalledTimes(1)
    expect(running.stores.imports.value()).toMatchObject({ source: 'lastpass-csv', preview: null, importId: '', fileName: '' })
  })

  it('does nothing when confirm runs without a preview', async () => {
    const running = harness()

    await running.controller.confirm()

    expect(vaultApi.commitImport).not.toHaveBeenCalled()
    expect(running.stores.imports.value().importing).toBe(false)
  })

  it('adds the previewed logins on confirm and names the result', async () => {
    const running = harness()
    vaultApi.commitImport.mockResolvedValue({
      importedEntries: 2,
      skippedExactDuplicates: 0,
      importedSecureNotes: 0,
      importedCards: 0,
      importedIdentities: 0,
      importedSshKeys: 0,
      snapshot: { entries: [] },
    })
    running.controller.open()
    running.stores.imports.patch({ importId: 'fictional-import', preview: preview() })

    await running.controller.confirm()

    expect(vaultApi.commitImport).toHaveBeenCalledWith('fictional-import', true)
    expect(running.modal.state.value().active).toBeNull()
    expect(running.feedback.state.value().notice?.message).toBe('2 logins were imported locally.')
    running.feedback.destroy()
  })
})

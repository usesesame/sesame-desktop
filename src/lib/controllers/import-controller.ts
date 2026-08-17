import type { AppStores } from '../stores/app-stores'
import type { ImportSource } from '../types'
import {
  cancelImport,
  chooseImportFile,
  commitImport,
  previewImportFile,
  recordDiagnostic,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface ImportControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  refreshDiagnostics: () => Promise<void>
  selectEntry: (id: string) => Promise<void>
}

export function createImportController({ stores, feedback, modal, refreshDiagnostics, selectEntry }: ImportControllerOptions) {
  const { imports, vault } = stores

  function reset() {
    // Rust owns the parsed secret-bearing rows; cancelling wipes them there.
    void cancelImport()
    imports.patch({ preview: null, importId: '', fileName: '', sourceMenuOpen: false, skipExactDuplicates: true })
  }

  function close() {
    if (imports.value().importing) return
    modal.close('import')
    reset()
  }

  return {
    open() {
      modal.open({ kind: 'import' })
    },
    close,
    reset,
    clearSecrets() {
      // Without reset, a file's worth of credentials stays resident after the lock.
      modal.closeAll()
      reset()
      imports.patch({ importing: false })
    },
    chooseSource(source: ImportSource) {
      const hadPreview = Boolean(imports.value().preview)
      if (hadPreview) void cancelImport()
      imports.patch({
        source,
        sourceMenuOpen: false,
        ...(hadPreview ? { preview: null, importId: '', fileName: '' } : {}),
      })
    },
    async chooseFile() {
      feedback.clearError()
      const source = imports.value().source
      let path: string | null
      try {
        path = await chooseImportFile(source)
      } catch (error) {
        feedback.setError(error)
        return
      }
      if (!path) return

      imports.patch({ importing: true })
      try {
        const { importId, preview } = await previewImportFile(path, source)
        imports.patch({ importId, fileName: path.split(/[\\/]/).pop() ?? path, preview })
      } catch (error) {
        void recordDiagnostic('import_preview', 'invalid_file')
        void refreshDiagnostics()
        feedback.setError(error)
      } finally {
        imports.patch({ importing: false })
      }
    },
    async confirm() {
      const pending = imports.value()
      if (!pending.importId || !pending.preview) return
      imports.patch({ importing: true })
      feedback.clearError()
      try {
        const result = await commitImport(pending.importId, pending.skipExactDuplicates)
        vault.patch({ snapshot: result.snapshot })
        modal.close('import')
        imports.patch({ preview: null, importId: '', fileName: '', sourceMenuOpen: false, skipExactDuplicates: true })
        const skipped = result.skippedExactDuplicates
          ? ` ${result.skippedExactDuplicates} exact ${result.skippedExactDuplicates === 1 ? 'duplicate was' : 'duplicates were'} skipped.`
          : ''
        const undo = result.revisionBackupName ? ` You can undo this by restoring ${result.revisionBackupName}.` : ''
        const notes = result.importedSecureNotes
          ? ` ${result.importedSecureNotes} secure ${result.importedSecureNotes === 1 ? 'note was' : 'notes were'} imported too.`
          : ''
        const cards = result.importedCards
          ? ` ${result.importedCards} ${result.importedCards === 1 ? 'card was' : 'cards were'} imported too.`
          : ''
        const identities = result.importedIdentities
          ? ` ${result.importedIdentities} saved ${result.importedIdentities === 1 ? 'identity was' : 'identities were'} imported too.`
          : ''
        feedback.showNotice('Import complete', `${result.importedEntries} ${result.importedEntries === 1 ? 'login was' : 'logins were'} imported locally.${notes}${cards}${identities}${skipped}${undo}`)
        if (result.snapshot.entries[0]) await selectEntry(result.snapshot.entries[0].id)
      } catch (error) {
        void recordDiagnostic('import_commit', 'failed')
        void refreshDiagnostics()
        feedback.setError(error)
      } finally {
        imports.patch({ importing: false })
      }
    },
  }
}

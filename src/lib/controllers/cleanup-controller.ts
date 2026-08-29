import type { AppStores } from '../stores/app-stores'
import type { CleanupEntry, DuplicateGroup, IssueKind, MergeChoices, MergeComparison, SecurityFilter } from '../types'
import {
  deleteLocalVault,
  deleteLogin,
  exportVaultCsv,
  getDuplicateGroups,
  getMergeComparison,
  grantPresence,
  mergeDuplicateLogins,
  PRESENCE_REQUIRED,
  recordDiagnostic,
} from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface CleanupControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  selectEntry: (id: string) => Promise<void>
  editEntry: (entry: CleanupEntry) => Promise<void>
  clearLoginSelection: () => void
  refreshDiagnostics: () => Promise<void>
  onVaultDeleted: (message: string) => void
}

export function createCleanupController(options: CleanupControllerOptions) {
  const { stores, feedback, modal } = options
  const { selection, totp, vault } = stores
  const state = controllerStore({
    duplicateReviewOpen: false,
    duplicateGroups: [] as DuplicateGroup[],
    duplicateGroupId: undefined as string | undefined,
    duplicateSelectedIds: [] as string[],
    duplicateReviewLoading: false,
    cleanupWorking: false,
    deleteCandidate: null as CleanupEntry | null,
    deleteBatch: [] as CleanupEntry[],
    mergeCandidate: null as { group: DuplicateGroup; entries: CleanupEntry[] } | null,
    mergeKeepId: '',
    mergeComparison: null as MergeComparison | null,
    mergeChoices: {} as MergeChoices,
    readableExportConfirmed: false,
    exportPresenceRequired: false,
    exportPresencePassword: '',
    deleteVaultPassword: '',
    dataActionWorking: false,
  })

  function matchesFilter(issueKinds: IssueKind[], filter: Exclude<SecurityFilter, null>) {
    return issueKinds.includes(filter)
  }

  async function loadDuplicateGroups() {
    state.patch({ duplicateReviewLoading: true })
    feedback.clearError()
    try {
      const groups = await getDuplicateGroups()
      state.patch({
        duplicateGroups: groups,
        duplicateGroupId: groups[0]?.id,
        duplicateSelectedIds: groups[0]?.entries.map((entry) => entry.id) ?? [],
      })
    } catch (error) {
      void recordDiagnostic('ui', 'handled_error')
      void options.refreshDiagnostics()
      feedback.setError(error)
    } finally {
      state.patch({ duplicateReviewLoading: false })
    }
  }

  async function runReadableExport() {
    state.patch({ dataActionWorking: true })
    feedback.clearError()
    try {
      const fileNames = await exportVaultCsv()
      if (fileNames?.length) {
        feedback.showNotice(
          'Readable export created',
          fileNames.length > 1
            ? `${fileNames.join(' and ')} contain unencrypted vault data.`
            : `${fileNames[0]} contains unencrypted login data.`,
        )
      }
      state.patch({ exportPresenceRequired: false, exportPresencePassword: '' })
    } catch (error) {
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) {
        state.patch({ exportPresenceRequired: true })
        feedback.setErrorMessage('Confirm your master password before Sesame writes a readable copy of your vault.')
      } else {
        feedback.setError(error)
      }
    } finally {
      state.patch({ dataActionWorking: false })
    }
  }

  return {
    state,
    loadDuplicateGroups,
    setDuplicateReviewOpen(open: boolean) { state.patch({ duplicateReviewOpen: open }) },
    async openDuplicateReview() {
      selection.patch({ activeView: 'security' })
      state.patch({ duplicateReviewOpen: true })
      await loadDuplicateGroups()
    },
    selectDuplicateGroup(groupId: string) {
      state.patch({
        duplicateGroupId: groupId,
        duplicateSelectedIds: state.value().duplicateGroups.find((group) => group.id === groupId)?.entries.map((entry) => entry.id) ?? [],
      })
    },
    selectDuplicateEntry(entryId: string, selected: boolean) {
      const ids = state.value().duplicateSelectedIds
      state.patch({ duplicateSelectedIds: selected ? [...new Set([...ids, entryId])] : ids.filter((id) => id !== entryId) })
    },
    async editCleanupEntry(entry: CleanupEntry) {
      await options.editEntry(entry)
      state.patch({ duplicateReviewOpen: false })
      selection.patch({ activeView: 'vault' })
    },
    requestDelete(entry: CleanupEntry) {
      const opened = modal.open({ kind: 'delete-login', entryId: entry.id })
      if (opened) state.patch({ deleteCandidate: entry, deleteBatch: [] })
    },
    requestBulkDelete(entries: CleanupEntry[]) {
      const [first] = entries
      if (!first) return
      const opened = modal.open({ kind: 'delete-login', entryId: first.id })
      if (opened) state.patch({ deleteCandidate: first, deleteBatch: entries })
    },
    cancelDelete() {
      modal.close('delete-login')
      state.patch({ deleteCandidate: null, deleteBatch: [] })
    },
    async requestMerge(group: DuplicateGroup, entries: CleanupEntry[]) {
      const opened = modal.open({ kind: 'merge' })
      if (!opened) return
      state.patch({ mergeCandidate: { group, entries }, mergeKeepId: entries[0]?.id ?? '', mergeChoices: {}, mergeComparison: null })
      try {
        state.patch({ mergeComparison: await getMergeComparison(entries.map((entry) => entry.id)) })
      } catch (error) {
        feedback.setError(error)
      }
    },
    setMergeKeepId(mergeKeepId: string) { state.patch({ mergeKeepId }) },
    setMergeChoices(mergeChoices: MergeChoices) { state.patch({ mergeChoices }) },
    cancelMerge() {
      modal.close('merge')
      state.patch({ mergeCandidate: null, mergeComparison: null, mergeChoices: {}, mergeKeepId: '' })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      const batch = state.value().deleteBatch
      const targets = batch.length ? batch : [candidate]
      state.patch({ cleanupWorking: true })
      feedback.clearError()
      try {
        let result = await deleteLogin(targets[0].id)
        for (const target of targets.slice(1)) result = await deleteLogin(target.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-login')
        state.patch({ deleteCandidate: null, deleteBatch: [] })
        const openCardDeleted = targets.some((target) => vault.value().loginCard?.id === target.id)
        if (openCardDeleted) {
          options.clearLoginSelection()
          if (result.snapshot.entries[0]) await options.selectEntry(result.snapshot.entries[0].id)
        }
        if (state.value().duplicateReviewOpen) await loadDuplicateGroups()
        feedback.showNotice(
          targets.length === 1 ? 'Login deleted' : 'Logins deleted',
          targets.length === 1
            ? `${candidate.title} was removed from your vault.`
            : `${targets.length} logins were removed from your vault.`,
        )
      } catch (error) {
        void recordDiagnostic('vault_save', 'failed')
        void options.refreshDiagnostics()
        feedback.setError(error)
      } finally {
        state.patch({ cleanupWorking: false })
      }
    },
    async confirmMerge() {
      const current = state.value()
      if (!current.mergeCandidate || !current.mergeKeepId) return
      state.patch({ cleanupWorking: true })
      feedback.clearError()
      try {
        const removeIds = current.mergeCandidate.entries.map((entry) => entry.id).filter((id) => id !== current.mergeKeepId)
        const result = await mergeDuplicateLogins(current.mergeKeepId, removeIds, current.mergeChoices)
        vault.patch({ snapshot: result.snapshot })
        modal.close('merge')
        state.patch({ mergeCandidate: null, mergeKeepId: '', mergeComparison: null, mergeChoices: {} })
        if (vault.value().loginCard && removeIds.includes(vault.value().loginCard!.id)) {
          totp.stop()
          await options.selectEntry(result.id)
        }
        await loadDuplicateGroups()
        const undo = result.revisionBackupName ? ` You can undo this by restoring ${result.revisionBackupName}.` : ''
        feedback.showNotice('Duplicates merged', `Sesame kept the values you chose.${undo}`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ cleanupWorking: false })
      }
    },
    clearSecurityFilter() { selection.patch({ securityFilter: null }) },
    async showSecurityFilter(filter: Exclude<SecurityFilter, null>) {
      selection.patch({ securityFilter: filter, categoryFilter: 'login', collectionFilter: null, searchQuery: '', activeView: 'vault' })
      const first = (vault.value().snapshot?.entries ?? [])
        .filter((entry) => matchesFilter(entry.issueKinds, filter))
        .sort((left, right) => left.title.localeCompare(right.title, undefined, { sensitivity: 'base' }))[0]
      if (first) await options.selectEntry(first.id)
    },
    openDataControls() {
      state.patch({ readableExportConfirmed: false, exportPresenceRequired: false, exportPresencePassword: '' })
      modal.open({ kind: 'data-controls' })
    },
    closeDataControls() { modal.close('data-controls') },
    setReadableExportConfirmed(readableExportConfirmed: boolean) { state.patch({ readableExportConfirmed }) },
    openDeleteVault() {
      modal.close('data-controls')
      state.patch({ deleteVaultPassword: '' })
      modal.open({ kind: 'delete-vault' })
    },
    closeDeleteVault() {
      modal.close('delete-vault')
      state.patch({ deleteVaultPassword: '' })
    },
    setDeleteVaultPassword(deleteVaultPassword: string) { state.patch({ deleteVaultPassword }) },
    async exportReadableVault() {
      if (!state.value().readableExportConfirmed) return
      await runReadableExport()
    },
    async confirmExportPresence() {
      const secret = state.value().exportPresencePassword
      if (!secret || state.value().dataActionWorking) return
      state.patch({ dataActionWorking: true })
      feedback.clearError()
      try {
        await grantPresence(secret)
        state.patch({ exportPresencePassword: '' })
        await runReadableExport()
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ dataActionWorking: false })
      }
    },
    async confirmDeleteVault() {
      const masterPassword = state.value().deleteVaultPassword
      if (!masterPassword) return
      state.patch({ dataActionWorking: true })
      feedback.clearError()
      try {
        await deleteLocalVault(masterPassword)
        options.clearLoginSelection()
        state.patch({
          duplicateReviewOpen: false, duplicateGroups: [], deleteVaultPassword: '',
        })
        options.onVaultDeleted('The local vault and Sesame backups were removed from this device.')
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ dataActionWorking: false })
      }
    },
    clearSecrets() {
      modal.closeAll()
      state.set({
        duplicateReviewOpen: false, duplicateGroups: [], duplicateGroupId: undefined, duplicateSelectedIds: [],
        duplicateReviewLoading: false, cleanupWorking: false, deleteCandidate: null, deleteBatch: [], mergeCandidate: null,
        mergeKeepId: '', mergeComparison: null, mergeChoices: {}, readableExportConfirmed: false,
        exportPresenceRequired: false, exportPresencePassword: '',
        deleteVaultPassword: '', dataActionWorking: false,
      })
    },
  }
}

import type { AppStores } from '../stores/app-stores'
import type { BreachScanReport, CleanupEntry, DuplicateGroup, IssueKind, MergeChoices, MergeComparison, SecurityFilter } from '../types'
import {
  cancelLoginBreachScan,
  deleteLocalVault,
  deleteLogin,
  exportVaultCsv,
  getDuplicateGroups,
  getLoginBreachScanStatus,
  getMergeComparison,
  grantPresence,
  mergeDuplicateLogins,
  onBreachScanFinished,
  onBreachScanProgress,
  PRESENCE_REQUIRED,
  recordDiagnostic,
  startLoginBreachScan,
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
    breachScan: null as BreachScanReport | null,
    breachScanError: '',
  })

  function matchesFilter(issueKinds: IssueKind[], filter: Exclude<SecurityFilter, null>) {
    return issueKinds.includes(filter)
  }

  let breachScanDisposed = false
  let stopBreachScanProgress: (() => void) | undefined
  let stopBreachScanFinished: (() => void) | undefined

  async function refreshBreachScan() {
    try {
      const report = await getLoginBreachScanStatus()
      if (!breachScanDisposed) state.patch({ breachScan: report })
    } catch {
      void recordDiagnostic('ui', 'handled_error')
      void options.refreshDiagnostics()
    }
  }

  let duplicateLoadGeneration = 0

  async function loadDuplicateGroups() {
    const generation = ++duplicateLoadGeneration
    state.patch({ duplicateReviewLoading: true })
    feedback.clearError()
    try {
      const groups = await getDuplicateGroups()
      if (generation !== duplicateLoadGeneration || !vault.value().status.unlocked) return
      state.patch({
        duplicateGroups: groups,
        duplicateGroupId: groups[0]?.id,
        duplicateSelectedIds: groups[0]?.entries.map((entry) => entry.id) ?? [],
      })
    } catch (error) {
      if (generation !== duplicateLoadGeneration) return
      void recordDiagnostic('ui', 'handled_error')
      void options.refreshDiagnostics()
      feedback.setError(error)
    } finally {
      if (generation === duplicateLoadGeneration) state.patch({ duplicateReviewLoading: false })
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
            ? `${fileNames.join(' and ')} contain unencrypted vault data. Open them as data, because a spreadsheet can run a cell that starts with a formula character.`
            : `${fileNames[0]} contains unencrypted login data. Open it as data, because a spreadsheet can run a cell that starts with a formula character.`,
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
      if (!candidate || state.value().cleanupWorking) return
      const batch = state.value().deleteBatch
      const targets = batch.length ? batch : [candidate]
      state.patch({ cleanupWorking: true })
      feedback.clearError()
      let lastSnapshot: Awaited<ReturnType<typeof deleteLogin>>['snapshot'] | null = null
      let deleted = 0
      try {
        for (const target of targets) {
          lastSnapshot = (await deleteLogin(target.id)).snapshot
          deleted += 1
          if (!vault.value().status.unlocked) break
        }
        if (lastSnapshot) vault.patch({ snapshot: lastSnapshot })
        modal.close('delete-login')
        state.patch({ deleteCandidate: null, deleteBatch: [] })
        if (deleted !== targets.length) {
          if (vault.value().status.unlocked) {
            feedback.setErrorMessage('Sesame removed some logins before the vault locked. The rest were left untouched.')
          }
          return
        }
        const openCardDeleted = targets.some((target) => vault.value().loginCard?.id === target.id)
        if (openCardDeleted) {
          options.clearLoginSelection()
          if (lastSnapshot?.entries[0]) await options.selectEntry(lastSnapshot.entries[0].id)
        }
        if (state.value().duplicateReviewOpen) await loadDuplicateGroups()
        feedback.showNotice(
          targets.length === 1 ? 'Login deleted' : 'Logins deleted',
          targets.length === 1
            ? `${candidate.title} was removed from your vault.`
            : `${targets.length} logins were removed from your vault.`,
        )
      } catch (error) {
        if (lastSnapshot) vault.patch({ snapshot: lastSnapshot })
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
    showCards() {
      selection.patch({ categoryFilter: 'card', securityFilter: null, collectionFilter: null, searchQuery: '', activeView: 'vault' })
    },
    async startBreachScan() {
      if (state.value().breachScan?.phase === 'running') return
      state.patch({ breachScanError: '', breachScan: { phase: 'running', checked: 0, total: 0, results: [] } })
      try {
        const report = await startLoginBreachScan()
        if (!breachScanDisposed) state.patch({ breachScan: report })
      } catch (error) {
        if (breachScanDisposed) return
        state.patch({
          breachScan: null,
          breachScanError: error instanceof Error ? error.message : 'Sesame could not start the breach check.',
        })
      }
    },
    async cancelBreachScan() {
      if (state.value().breachScan?.phase !== 'running') return
      try {
        await cancelLoginBreachScan()
      } catch {
        void recordDiagnostic('ui', 'handled_error')
      }
    },
    async refreshBreachScan() {
      await refreshBreachScan()
    },
    start() {
      breachScanDisposed = false
      void onBreachScanProgress((progress) => {
        const current = state.value().breachScan
        if (!current || current.phase !== 'running') return
        state.patch({ breachScan: { ...current, phase: 'running', checked: progress.checked, total: progress.total } })
      })
        .then((stop) => { if (breachScanDisposed) stop(); else stopBreachScanProgress = stop })
        .catch(() => void recordDiagnostic('renderer', 'breach_scan_listener_failed'))
      void onBreachScanFinished(() => { if (!breachScanDisposed) void refreshBreachScan() })
        .then((stop) => { if (breachScanDisposed) stop(); else stopBreachScanFinished = stop })
        .catch(() => void recordDiagnostic('renderer', 'breach_scan_listener_failed'))
      void refreshBreachScan()
      return () => {
        breachScanDisposed = true
        stopBreachScanProgress?.()
        stopBreachScanFinished?.()
        stopBreachScanProgress = undefined
        stopBreachScanFinished = undefined
      }
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
      duplicateLoadGeneration += 1
      modal.closeAll()
      state.set({
        duplicateReviewOpen: false, duplicateGroups: [], duplicateGroupId: undefined, duplicateSelectedIds: [],
        duplicateReviewLoading: false, cleanupWorking: false, deleteCandidate: null, deleteBatch: [], mergeCandidate: null,
        mergeKeepId: '', mergeComparison: null, mergeChoices: {}, readableExportConfirmed: false,
        exportPresenceRequired: false, exportPresencePassword: '',
        deleteVaultPassword: '', dataActionWorking: false, breachScan: null, breachScanError: '',
      })
    },
  }
}

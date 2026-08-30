import type { AppStores } from '../stores/app-stores'
import type { BreachCheckResult, CleanupEntry, Folder, LoginInput, VaultEntry } from '../types'
import { derived } from 'svelte/store'
import { makePassword } from '../generator'
import {
  autoType,
  bulkAssignFolder,
  checkPasswordBreach,
  copyToClipboard,
  createFolder,
  deleteFolder,
  getLoginCard,
  grantPresence,
  openWebsite,
  PRESENCE_REQUIRED,
  recordDiagnostic,
  renameFolder,
  recordItemUse,
  revealLoginSecret,
  saveLogin,
  setItemFavourite,
} from '../vault'
import { FAVOURITES_FILTER, RECENT_FILTER, rememberRecent } from '../vault-collections'
import { vaultItems } from '../vault-items'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

const AUTO_TYPE_COUNTDOWN_SECONDS = 3

  function copyFieldLabel(field: 'username' | 'email' | 'password'): string {
  return field === 'username' ? 'Username' : field === 'email' ? 'Email' : 'Password'
}

function emptyLoginDraft(password = ''): LoginInput {
  return {
    title: '', url: '', urls: [], tags: [], username: '', email: '', password, folder: '', totp: undefined, backupCodes: [],
    recoveryEmail: '', recoveryPhone: '', recoveryNotApplicable: false, notes: '',
  }
}

interface LoginControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  refreshDiagnostics: () => Promise<void>
  requestDelete: (entry: CleanupEntry) => void
  requestBulkDelete: (entries: CleanupEntry[]) => void
}

export function createLoginController({ stores, feedback, modal, refreshDiagnostics, requestDelete, requestBulkDelete }: LoginControllerOptions) {
  const { selection, settings, totp, vault } = stores
  const state = controllerStore({
    passwordVisible: false,
    revealedPassword: '',
    revealedFor: '',
    passwordPresenceRequired: false,
    passwordPresenceSecret: '',
    savingLogin: false,
    editorTitle: 'Add a login',
    editorFocusUrl: false,
    editorHasTotp: false,
    loginDraft: emptyLoginDraft(),
    entryMenu: null as { id: string; x: number; y: number } | null,
    folderWorking: false,
    folderAction: null as { kind: 'move' | 'rename'; ids: string[]; folderId?: string; name: string } | null,
    recoveryActionWorking: false,
    // Session-only: sent only in the breach-check request itself.
    breachCheckEntryId: '',
    breachCheckOpen: false,
    breachCheckWorking: false,
    breachCheckResult: null as BreachCheckResult | null,
    breachCheckError: '',
    autoTypeEntryId: '',
    autoTypeCountdown: 0,
    multiSelect: false,
    selectedIds: [] as string[],
    bulkFolderId: '',
  })
  let selectionRequestToken = 0
  let autoTypeTimer: ReturnType<typeof setTimeout> | null = null

  function stopAutoTypeCountdown() {
    if (autoTypeTimer) clearTimeout(autoTypeTimer)
    autoTypeTimer = null
  }
  const folderOptions = derived(vault, ($vault) => [...($vault.snapshot?.folders ?? [])].sort((left, right) => left.name.localeCompare(right.name)))
  const contextEntry = derived([state, vault], ([$state, $vault]) => $state.entryMenu
    ? $vault.snapshot?.entries.find((entry) => entry.id === $state.entryMenu?.id) ?? null
    : null)
  const loginIds = derived(vault, ($vault) => new Set(($vault.snapshot?.entries ?? []).map((entry) => entry.id)))

  async function ensureRevealed(id: string): Promise<string> {
    if (state.value().revealedFor === id && state.value().revealedPassword) {
      return state.value().revealedPassword
    }
    try {
      const secret = await revealLoginSecret(id)
      state.patch({ revealedPassword: secret, revealedFor: id, passwordPresenceRequired: false })
      return secret
    } catch (error) {
      if (error instanceof Error && error.message === PRESENCE_REQUIRED) {
        state.patch({ passwordPresenceRequired: true, revealedFor: id, passwordPresenceSecret: '' })
        feedback.setErrorMessage('Confirm your master password to show the saved password.')
      } else {
        feedback.setError(error)
      }
      return ''
    }
  }

  async function selectEntry(id: string) {
    selectionRequestToken += 1
    const requestToken = selectionRequestToken
    totp.stop()
    selection.patch({ activeItemId: id, activeItemKind: 'login' })
    feedback.clearError()
    if (state.value().breachCheckEntryId !== id) {
      state.patch({ breachCheckEntryId: id, breachCheckOpen: false, breachCheckWorking: false, breachCheckResult: null, breachCheckError: '' })
    }
    if (state.value().autoTypeEntryId !== id) {
      stopAutoTypeCountdown()
      state.patch({ autoTypeEntryId: '', autoTypeCountdown: 0 })
    }
    try {
      const card = await getLoginCard(id)
      if (requestToken !== selectionRequestToken || selection.value().activeItemId !== id || !vault.value().status.unlocked) return
      vault.patch({ loginCard: card })
      selection.patch({ recentItemIds: rememberRecent(selection.value().recentItemIds, id) })
      state.patch({ passwordVisible: false, revealedPassword: '', revealedFor: '', passwordPresenceRequired: false, passwordPresenceSecret: '' })
      totp.start(card, id, (refresh) => {
        const current = vault.value().loginCard
        if (requestToken !== selectionRequestToken || selection.value().activeItemId !== id || !current) return
        vault.patch({ loginCard: { ...current, totpCode: refresh.totpCode ?? undefined, totpRemaining: refresh.totpRemaining ?? undefined } })
      }, () => {
        void recordDiagnostic('totp_refresh', 'failed')
        void refreshDiagnostics()
      })
    } catch (error) {
      if (requestToken === selectionRequestToken && selection.value().activeItemId === id) feedback.setError(error)
    }
  }

  async function copy(value: string, label: string) {
    try {
      await copyToClipboard(value)
      const activeId = selection.value().activeItemId
      if (activeId && ['Username', 'Email', 'Password', '2FA code', 'Backup codes'].includes(label)) void markUsed(activeId)
      const clearSeconds = settings.value().clipboardClearSeconds
      feedback.showNotice(`${label} copied`, `Clears after ${clearSeconds} seconds if the clipboard has not changed.`)
    } catch (error) {
      void recordDiagnostic('clipboard', 'failed')
      void refreshDiagnostics()
      feedback.setError(error)
    }
  }

  async function markUsed(id: string) {
    try {
      const snapshot = await recordItemUse(id)
      vault.patch({ snapshot })
      const card = vault.value().loginCard
      const entry = snapshot.entries.find((candidate) => candidate.id === id)
      if (card?.id === id) vault.patch({ loginCard: { ...card, lastUsedAt: entry?.lastUsedAt } })
    } catch {
      void recordDiagnostic('ui', 'handled_error')
    }
  }

  async function changeFavourite(id: string, favourite: boolean) {
    try {
      const snapshot = await setItemFavourite(id, favourite)
      vault.patch({ snapshot })
      const card = vault.value().loginCard
      if (card?.id === id) vault.patch({ loginCard: { ...card, favourite } })
      feedback.showNotice(favourite ? 'Added to favourites' : 'Removed from favourites', favourite ? 'This login now stays near the top.' : 'The login remains in its folder.')
    } catch (error) {
      feedback.setError(error)
    }
  }

  function closeEditor() {
    modal.close('login-editor')
    state.patch({ loginDraft: emptyLoginDraft(), editorHasTotp: false })
  }

  function openEditor() {
    const card = vault.value().loginCard
    if (!card) return
    const opened = modal.open({ kind: 'login-editor' })
    if (!opened) return
    state.patch({
      loginDraft: {
        id: card.id, title: card.title, url: card.url, urls: card.urls?.slice(1) ?? [], tags: card.tags ?? [], username: card.username, email: card.email, password: '',
        folder: card.folder, folderId: card.folderId, totp: undefined, backupCodes: card.backupCodes || [],
        recoveryEmail: card.recoveryEmail || '', recoveryPhone: card.recoveryPhone || '',
        recoveryNotApplicable: card.recoveryNotApplicable, notes: card.notes || '',
      },
      editorHasTotp: card.hasTotp,
      editorTitle: 'Edit login', editorFocusUrl: false,
    })
    feedback.clearError()
  }

  async function contextCard(id: string) {
    try {
      return await getLoginCard(id)
    } catch (error) {
      state.patch({ entryMenu: null })
      feedback.setError(error)
      return null
    }
  }

  async function assignFolder(ids: string[], folderId: string | undefined, message: string) {
    if (state.value().folderWorking || !ids.length) return false
    state.patch({ folderWorking: true })
    feedback.clearError()
    try {
      const snapshot = await bulkAssignFolder(ids, folderId)
      vault.patch({ snapshot })
      const card = vault.value().loginCard
      if (card && ids.includes(card.id)) {
        const folder = snapshot.folders.find((candidate) => candidate.id === folderId)
        vault.patch({ loginCard: { ...card, folderId: folder?.id, folder: folder?.name ?? '' } })
      }
      feedback.showNotice('Folders updated', message)
      return true
    } catch (error) {
      feedback.setError(error)
      return false
    } finally {
      state.patch({ folderWorking: false })
    }
  }

  function clearMultiSelect() {
    state.patch({ multiSelect: false, selectedIds: [], bulkFolderId: '' })
  }

  async function bulkMoveSelected() {
    const current = state.value()
    if (!current.selectedIds.length) return
    const folderId = current.bulkFolderId || undefined
    const folder = vault.value().snapshot?.folders.find((candidate) => candidate.id === folderId)
    const count = current.selectedIds.length
    const moved = await assignFolder(
      current.selectedIds,
      folderId,
      folder ? `${count} ${count === 1 ? 'item' : 'items'} moved to ${folder.name}.` : `${count} ${count === 1 ? 'item' : 'items'} moved to Unfiled.`,
    )
    if (moved) clearMultiSelect()
  }

  async function bulkFavouriteSelected() {
    const current = state.value()
    if (!current.selectedIds.length || current.folderWorking) return
    const entries = vaultItems(vault.value().snapshot).filter((item) => current.selectedIds.includes(item.id))
    if (!entries.length) return
    const favourite = !entries.every((entry) => entry.favourite)
    state.patch({ folderWorking: true })
    feedback.clearError()
    try {
      let snapshot = vault.value().snapshot
      for (const entry of entries) {
        if (entry.favourite === favourite) continue
        snapshot = await setItemFavourite(entry.id, favourite)
      }
      if (snapshot) vault.patch({ snapshot })
      const card = vault.value().loginCard
      if (card && current.selectedIds.includes(card.id)) vault.patch({ loginCard: { ...card, favourite } })
      const count = entries.length
      feedback.showNotice(
        favourite ? 'Added to favourites' : 'Removed from favourites',
        `${count} ${count === 1 ? 'item' : 'items'} updated.`,
      )
      clearMultiSelect()
    } catch (error) {
      feedback.setError(error)
    } finally {
      state.patch({ folderWorking: false })
    }
  }

  function bulkDeleteSelected() {
    const current = state.value()
    if (!current.selectedIds.length) return
    const entries = (vault.value().snapshot?.entries ?? [])
      .filter((entry) => current.selectedIds.includes(entry.id))
      .map((entry) => ({ id: entry.id, title: entry.title, site: entry.site, username: '', initials: entry.initials, reason: '' }))
    if (!entries.length) return
    requestBulkDelete(entries)
  }

  return {
    state,
    folderOptions,
    contextEntry,
    loginIds,
    selectEntry,
    copy,
    openNew(password = '') {
      const opened = modal.open({ kind: 'login-editor' })
      if (!opened) return
      state.patch({ loginDraft: emptyLoginDraft(password), editorHasTotp: false, editorTitle: 'Add a login', editorFocusUrl: false })
      feedback.clearError()
    },
    openEditor,
    openEditorWebsite() {
      openEditor()
      state.patch({ editorFocusUrl: true })
    },
    openEditorWithFreshPassword() {
      openEditor()
      const draft = state.value().loginDraft
      if (!draft.id) return
      state.patch({ loginDraft: { ...draft, password: makePassword({ length: 20, options: { lowercase: true, uppercase: true, numbers: true, symbols: true }, avoidAmbiguous: true } ) } })
    },
    closeEditor,
    async togglePasswordReveal() {
      const card = vault.value().loginCard
      if (!card?.hasPassword) return
      if (state.value().passwordVisible) {
        state.patch({ passwordVisible: false })
        return
      }
      const secret = await ensureRevealed(card.id)
      if (secret) state.patch({ passwordVisible: true })
    },
    async confirmPasswordPresence() {
      const secret = state.value().passwordPresenceSecret
      const id = state.value().revealedFor
      if (!secret || !id) return
      state.patch({ passwordPresenceSecret: '' })
      try {
        await grantPresence(secret)
      } catch (error) {
        feedback.setError(error)
        return
      }
      const revealed = await ensureRevealed(id)
      if (revealed) state.patch({ passwordPresenceRequired: false, passwordVisible: true })
    },
    cancelPasswordPresence() {
      state.patch({ passwordPresenceRequired: false, passwordPresenceSecret: '' })
    },
    toggleBreachCheck() {
      const card = vault.value().loginCard
      if (!card) return
      if (state.value().breachCheckEntryId !== card.id) {
        state.patch({ breachCheckEntryId: card.id, breachCheckResult: null, breachCheckError: '' })
      }
      state.patch({ breachCheckOpen: !state.value().breachCheckOpen })
    },
    async runBreachCheck() {
      const card = vault.value().loginCard
      if (!card?.hasPassword || state.value().breachCheckWorking) return
      const secret = await ensureRevealed(card.id)
      if (!secret) return
      state.patch({ breachCheckWorking: true, breachCheckError: '' })
      try {
        const result = await checkPasswordBreach(secret)
        state.patch({ breachCheckResult: result })
      } catch (error) {
        state.patch({ breachCheckError: error instanceof Error ? error.message : 'Sesame could not reach the breach-check service. Try again.' })
      } finally {
        state.patch({ breachCheckWorking: false })
      }
    },
    startAutoType() {
      const card = vault.value().loginCard
      if (!card || state.value().autoTypeCountdown > 0) return
      stopAutoTypeCountdown()
      state.patch({ autoTypeEntryId: card.id, autoTypeCountdown: AUTO_TYPE_COUNTDOWN_SECONDS })
      const tick = () => {
        const remaining = state.value().autoTypeCountdown - 1
        if (remaining <= 0) {
          state.patch({ autoTypeCountdown: 0 })
          void (async () => {
            feedback.clearError()
            try {
              await autoType(card.id)
              feedback.showNotice('Typed', 'Sesame sent the saved sign-in details to the focused window.')
            } catch (error) {
              feedback.setError(error)
            } finally {
              if (state.value().autoTypeEntryId === card.id) state.patch({ autoTypeEntryId: '' })
            }
          })()
          return
        }
        state.patch({ autoTypeCountdown: remaining })
        autoTypeTimer = setTimeout(tick, 1000)
      }
      autoTypeTimer = setTimeout(tick, 1000)
    },
    cancelAutoType() {
      stopAutoTypeCountdown()
      state.patch({ autoTypeEntryId: '', autoTypeCountdown: 0 })
    },
    requestCurrentDelete() {
      const card = vault.value().loginCard
      if (!card) return
      closeEditor()
      requestDelete({ id: card.id, title: card.title, site: card.site, username: card.username, initials: card.initials, reason: '' })
    },
    async markRecoveryNotApplicable() {
      const card = vault.value().loginCard
      if (!card || state.value().recoveryActionWorking) return
      state.patch({ recoveryActionWorking: true })
      feedback.clearError()
      try {
        const result = await saveLogin({
          id: card.id, title: card.title, url: card.url, urls: card.urls?.slice(1) ?? [], tags: card.tags ?? [], username: card.username, email: card.email, password: '',
          folder: card.folder, folderId: card.folderId, totp: undefined, backupCodes: [], recoveryEmail: '', recoveryPhone: '',
          recoveryNotApplicable: true, notes: card.notes || '',
        })
        vault.patch({ snapshot: result.snapshot, loginCard: { ...card, backupCodes: undefined, recoveryEmail: undefined, recoveryPhone: undefined, recoveryNotApplicable: true } })
        feedback.showNotice('Recovery checked', `${card.title} is marked as having no separate recovery options.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ recoveryActionWorking: false })
      }
    },
    async submit(totpEntered: boolean) {
      const draft = state.value().loginDraft
      state.patch({ savingLogin: true })
      feedback.clearError()
      try {
        const result = await saveLogin({ ...draft, totp: totpEntered ? draft.totp : undefined, backupCodes: draft.backupCodes.flatMap((value) => value.split(/[\n,]/)).map((value) => value.trim()).filter(Boolean) })
        vault.patch({ snapshot: result.snapshot })
        const savedEntry = result.snapshot.entries.find((entry) => entry.id === result.id)
        selection.patch({ collectionFilter: savedEntry?.folderId ?? null, securityFilter: null, searchQuery: '' })
        modal.close('login-editor')
        state.patch({ loginDraft: emptyLoginDraft() })
        await selectEntry(result.id)
        feedback.showNotice(draft.id ? 'Login updated' : 'Login saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingLogin: false })
      }
    },
    openEntryMenu(position: { x: number; y: number }, id: string) {
      state.patch({ entryMenu: { id, ...position } })
      if (selection.value().activeItemId !== id) void selectEntry(id)
    },
    closeEntryMenu() { state.patch({ entryMenu: null }) },
    openFolderManager() {
      modal.open({ kind: 'folder-manager' })
    },
    closeFolderManager() { modal.close('folder-manager') },
    async openContextSite(id: string) {
      const card = await contextCard(id)
      state.patch({ entryMenu: null })
      if (card?.url) {
        await openWebsite(card.url)
        void markUsed(id)
      }
    },
    async openCurrentWebsite(url: string) {
      await openWebsite(url)
      const id = selection.value().activeItemId
      if (id) void markUsed(id)
    },
    async copySelectedField(field: 'username' | 'email' | 'password') {
      const card = vault.value().loginCard
      if (!card) return
      const value = field === 'password' ? await ensureRevealed(card.id) : card[field]
      if (value) await copy(value, copyFieldLabel(field))
      else if (field !== 'password' || card.hasPassword) feedback.showNotice('Nothing to copy', `No ${field} is saved for this login.`)
    },
    async copyContextField(id: string, field: 'username' | 'email' | 'password') {
      const card = await contextCard(id)
      state.patch({ entryMenu: null })
      const value = field === 'password' ? await ensureRevealed(id) : card?.[field]
      if (value) await copy(value, copyFieldLabel(field))
      else if (card) feedback.showNotice('Nothing to copy', `No ${field} is saved for this login.`)
    },
    async editContext(id: string) {
      state.patch({ entryMenu: null })
      await selectEntry(id)
      openEditor()
    },
    deleteContext(entry: VaultEntry) {
      state.patch({ entryMenu: null })
      requestDelete({ id: entry.id, title: entry.title, site: entry.site, username: '', initials: entry.initials, reason: '' })
    },
    async moveContext(folderId?: string) {
      const id = state.value().entryMenu?.id
      if (!id) return
      const folder = vault.value().snapshot?.folders.find((candidate) => candidate.id === folderId)
      if (!await assignFolder([id], folderId, folder ? `Login moved to ${folder.name}.` : 'Login moved to Unfiled.')) return
      state.patch({ entryMenu: null })
      if (selection.value().collectionFilter !== null && ![FAVOURITES_FILTER, RECENT_FILTER].includes(selection.value().collectionFilter ?? '')) selection.patch({ collectionFilter: folderId ?? '' })
    },
    async bulkMove(ids: string[], folderId?: string) {
      const folder = vault.value().snapshot?.folders.find((candidate) => candidate.id === folderId)
      return assignFolder(ids, folderId, folder ? `${ids.length} ${ids.length === 1 ? 'login' : 'logins'} moved to ${folder.name}.` : `${ids.length} ${ids.length === 1 ? 'login' : 'logins'} moved to Unfiled.`)
    },
    toggleFavourite: changeFavourite,
    async toggleContextFavourite(id: string, favourite: boolean) {
      state.patch({ entryMenu: null })
      await changeFavourite(id, favourite)
    },
    startMultiSelect(id?: string) {
      state.patch({ multiSelect: true, selectedIds: id ? [id] : [], bulkFolderId: '' })
    },
    toggleMultiSelect(id: string, selected: boolean) {
      const ids = state.value().selectedIds
      state.patch({ selectedIds: selected ? [...new Set([...ids, id])] : ids.filter((candidate) => candidate !== id) })
    },
    selectVisible(ids: string[]) {
      state.patch({ multiSelect: true, selectedIds: [...new Set(ids)] })
    },
    setBulkFolderId(bulkFolderId: string) { state.patch({ bulkFolderId }) },
    bulkMoveSelected,
    bulkFavouriteSelected,
    bulkDeleteSelected,
    clearMultiSelect,
    startNewFolderForContext() {
      const menu = state.value().entryMenu
      if (!menu) return
      const opened = modal.open({ kind: 'folder-name' })
      if (!opened) return
      state.patch({ folderAction: { kind: 'move', ids: [menu.id], name: '' }, entryMenu: null })
    },
    startRenameFolder(folder: Folder) {
      const opened = modal.open({ kind: 'folder-name' })
      if (!opened) return
      state.patch({ folderAction: { kind: 'rename', ids: [], folderId: folder.id, name: folder.name } })
    },
    async unfileFolder(folder: Folder) {
      if (state.value().folderWorking) return
      state.patch({ folderWorking: true })
      feedback.clearError()
      try {
        const count = (vault.value().snapshot?.entries ?? []).filter((entry) => entry.folderId === folder.id).length
        const snapshot = await deleteFolder(folder.id)
        vault.patch({ snapshot })
        if (selection.value().collectionFilter === folder.id) selection.patch({ collectionFilter: '' })
        const card = vault.value().loginCard
        if (card?.folderId === folder.id) vault.patch({ loginCard: { ...card, folderId: undefined, folder: '' } })
        feedback.showNotice('Folder removed', `${count} ${count === 1 ? 'login was' : 'logins were'} moved to Unfiled.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ folderWorking: false })
      }
    },
    setFolderActionName(name: string) {
      const action = state.value().folderAction
      if (action) state.patch({ folderAction: { ...action, name } })
    },
    closeFolderAction() {
      modal.close('folder-name')
      state.patch({ folderAction: null })
    },
    async confirmFolderAction() {
      const action = state.value().folderAction
      if (!action) return
      const name = action.name.trim()
      if (!name || (action.kind === 'rename' && vault.value().snapshot?.folders.find((folder) => folder.id === action.folderId)?.name === name)) {
        modal.close('folder-name')
        state.patch({ folderAction: null })
        return
      }
      state.patch({ folderWorking: true })
      feedback.clearError()
      try {
        if (action.kind === 'rename' && action.folderId) {
          const snapshot = await renameFolder(action.folderId, name)
          vault.patch({ snapshot })
          const card = vault.value().loginCard
          if (card?.folderId === action.folderId) vault.patch({ loginCard: { ...card, folder: name } })
          feedback.showNotice('Folder renamed', `Folder renamed to ${name}.`)
        } else {
          let snapshot = await createFolder(name)
          const folder = snapshot.folders.find((candidate) => candidate.name.localeCompare(name, undefined, { sensitivity: 'base' }) === 0)
          if (!folder) throw new Error('Sesame created the folder but could not select it.')
          snapshot = await bulkAssignFolder(action.ids, folder.id)
          vault.patch({ snapshot })
          if (selection.value().collectionFilter !== null) selection.patch({ collectionFilter: folder.id })
          feedback.showNotice('Folder created', `Login moved to ${folder.name}.`)
        }
        modal.close('folder-name')
        state.patch({ folderAction: null })
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ folderWorking: false })
      }
    },
    clearSelection() {
      selectionRequestToken += 1
      totp.stop()
      vault.patch({ loginCard: null })
    },
    clearSecrets() {
      selectionRequestToken += 1
      totp.stop()
      modal.closeAll()
      // A countdown in flight must not fire after the lock it was racing against.
      stopAutoTypeCountdown()
      state.set({
        passwordVisible: false, revealedPassword: '', revealedFor: '', passwordPresenceRequired: false, passwordPresenceSecret: '',
        savingLogin: false, editorTitle: 'Add a login',
        editorFocusUrl: false, editorHasTotp: false, loginDraft: emptyLoginDraft(),
        entryMenu: null, folderWorking: false, folderAction: null, recoveryActionWorking: false,
        breachCheckEntryId: '', breachCheckOpen: false, breachCheckWorking: false, breachCheckResult: null, breachCheckError: '',
        autoTypeEntryId: '', autoTypeCountdown: 0,
        multiSelect: false, selectedIds: [], bulkFolderId: '',
      })
      vault.patch({ loginCard: null })
      selection.patch({ activeItemId: null, activeItemKind: null, recentItemIds: [] })
    },
  }
}

export type LoginController = ReturnType<typeof createLoginController>

import type { AppStores } from '../stores/app-stores'
import type { PendingChangeList, PendingChangeView } from '../types'
import {
  discardPendingLogin,
  goBackPendingChange,
  keepPendingChange,
  listPendingChanges,
  onPendingChangesChanged,
  previewMode,
  recordDiagnostic,
} from '../vault'
import type { FeedbackController } from './feedback-controller'
import { isolatedVaultText } from '../vault-text'

interface PendingChangesControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  editLogin: (id: string) => void
  copyPassword: (id: string) => Promise<void>
  openHistory: (id: string) => void
}

export function changedSince(change: PendingChangeView): boolean {
  return change.kind === 'change' && (change.superseded || (!change.canGoBack && change.daysLeft !== undefined))
}

export function pendingChangeMessage(change: PendingChangeView): string {
  const title = isolatedVaultText(change.title)
  if (change.kind === 'new') {
    return change.username
      ? `You signed up on ${change.host} as ${isolatedVaultText(change.username)}. Keep this login if the site accepted it.`
      : `Sesame saved a new login for ${change.host}. Keep it if the site accepted it.`
  }
  if (change.superseded) {
    return `A newer password was saved for ${title} since this one. Open its history to see each version.`
  }
  if (changedSince(change)) {
    return `${title} changed after Sesame saved this password. Open its history to see each version.`
  }
  if (change.fill === 'notFilled') {
    return `The browser could not fill the new password for ${title}. Go back to the old password.`
  }
  if (change.urgent && change.daysLeft !== undefined) {
    const days = change.daysLeft === 1 ? '1 day' : `${change.daysLeft} days`
    return `The new password for ${title} is still not confirmed. The old one leaves history in ${days}.`
  }
  if (!change.canGoBack) {
    return `The new password for ${title} is not confirmed. The old one is no longer in history.`
  }
  return `Sesame saved a new password for ${title}. Keep it if the site accepted it.`
}

export function createPendingChangesController({ stores, feedback, editLogin, copyPassword, openHistory }: PendingChangesControllerOptions) {
  const { pendingChanges, vault } = stores
  let disposed = false
  let stopListener: (() => void) | undefined
  let unsubscribeVault: (() => void) | undefined
  let lastRevision = -1

  function apply(list: PendingChangeList) {
    pendingChanges.patch({ changes: list.changes })
    if (list.snapshot && !previewMode) vault.patch({ snapshot: list.snapshot })
  }

  async function refresh() {
    if (!vault.value().snapshot) {
      pendingChanges.patch({ changes: [] })
      return
    }
    try {
      const list = await listPendingChanges()
      if (!disposed) apply(list)
    } catch {
      void recordDiagnostic('browser_host', 'pending_listener_failed')
    }
  }

  async function act(change: PendingChangeView, run: (id: string) => Promise<PendingChangeList>, title: string, message: string) {
    if (pendingChanges.value().working) return
    pendingChanges.patch({ working: change.id })
    try {
      apply(await run(change.id))
      feedback.showNotice(title, message)
    } catch (error) {
      feedback.setError(error)
    } finally {
      pendingChanges.patch({ working: null })
    }
  }

  return {
    refresh,
    keep(change: PendingChangeView) {
      if (change.kind === 'new') return act(change, keepPendingChange, 'Login kept', `${change.title} stays in your vault.`)
      if (changedSince(change)) return act(change, keepPendingChange, 'Notice closed', `The earlier passwords stay in the history of ${change.title}.`)
      return act(change, keepPendingChange, 'New password kept', `${change.title} keeps the new password.`)
    },
    goBack: (change: PendingChangeView) => act(change, goBackPendingChange, 'Old password restored', `The new one is still in the history of ${change.title}.`),
    discard: (change: PendingChangeView) => act(change, discardPendingLogin, 'Login moved to Trash', 'You can restore it from Trash for 30 days.'),
    copy: (change: PendingChangeView) => copyPassword(change.itemId),
    edit(change: PendingChangeView) {
      editLogin(change.itemId)
    },
    openHistory(change: PendingChangeView) {
      openHistory(change.itemId)
    },
    clearSecrets() {
      pendingChanges.patch({ changes: [], working: null })
    },
    start() {
      disposed = false
      unsubscribeVault = vault.subscribe((state) => {
        const revision = state.snapshot ? state.snapshot.revision : -1
        if (revision === lastRevision) return
        lastRevision = revision
        void refresh()
      })
      void onPendingChangesChanged(() => { if (!disposed) void refresh() })
        .then((stop) => {
          if (disposed) stop()
          else stopListener = stop
        })
        .catch(() => void recordDiagnostic('browser_host', 'pending_listener_failed'))
      return () => {
        disposed = true
        stopListener?.()
        unsubscribeVault?.()
        stopListener = undefined
        unsubscribeVault = undefined
      }
    },
  }
}

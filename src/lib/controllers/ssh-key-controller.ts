import type { AppStores } from '../stores/app-stores'
import type { SshKey, SshKeyInput } from '../types'
import { deleteSshKey, getSshKey, recordDiagnostic, saveSshKey } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyKeyDraft(): SshKeyInput {
  return { title: '', keyType: '', privateKey: '', publicKey: '', passphrase: '', notes: '', tags: [] }
}

function draftFrom(key: SshKey): SshKeyInput {
  const { id, title, keyType, privateKey, publicKey, passphrase, notes, tags } = key
  return { id, title, keyType, privateKey, publicKey, passphrase, notes, tags }
}

interface SshKeyControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createSshKeyController({ stores, feedback, modal }: SshKeyControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    keyDraft: emptyKeyDraft(),
    editorTitle: 'Add a key',
    savingKey: false,
    loadingKey: false,
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('ssh-key-editor')
    state.patch({ keyDraft: emptyKeyDraft() })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'ssh-key-editor' })
      if (!opened) return
      state.patch({ keyDraft: emptyKeyDraft(), editorTitle: 'Add a key' })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'ssh-key-editor' })
      if (!opened) return
      state.patch({ loadingKey: true })
      feedback.clearError()
      try {
        const key = await getSshKey(id)
        state.patch({ keyDraft: draftFrom(key), editorTitle: 'Edit key' })
      } catch (error) {
        modal.close('ssh-key-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingKey: false })
      }
    },
    closeEditor,
    setDraft(keyDraft: SshKeyInput) {
      state.patch({ keyDraft })
    },
    async save() {
      const draft = state.value().keyDraft
      state.patch({ savingKey: true })
      feedback.clearError()
      try {
        const result = await saveSshKey(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Key updated' : 'Key saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingKey: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-ssh-key', keyId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-ssh-key')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteSshKey(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-ssh-key')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Key deleted', `${candidate.title} was removed from your vault.`)
      } catch (error) {
        void recordDiagnostic('vault_save', 'failed')
        feedback.setError(error)
      } finally {
        state.patch({ deleteWorking: false })
      }
    },
    clearSecrets() {
      modal.closeAll()
      state.set({
        keyDraft: emptyKeyDraft(),
        editorTitle: 'Add a key',
        savingKey: false,
        loadingKey: false,
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type SshKeyController = ReturnType<typeof createSshKeyController>

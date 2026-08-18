import type { AppStores } from '../stores/app-stores'
import type { WifiNetwork, WifiNetworkInput } from '../types'
import { deleteWifiNetwork, getWifiNetwork, recordDiagnostic, saveWifiNetwork } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyNetworkDraft(): WifiNetworkInput {
  return { title: '', ssid: '', password: '', securityType: '', notes: '', tags: [] }
}

function draftFrom(network: WifiNetwork): WifiNetworkInput {
  const { id, title, ssid, password, securityType, notes, tags } = network
  return { id, title, ssid, password, securityType, notes, tags: tags ?? [] }
}

interface WifiNetworkControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createWifiNetworkController({ stores, feedback, modal }: WifiNetworkControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    networkDraft: emptyNetworkDraft(),
    editorTitle: 'Add a network',
    savingNetwork: false,
    loadingNetwork: false,
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('wifi-network-editor')
    state.patch({ networkDraft: emptyNetworkDraft() })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'wifi-network-editor' })
      if (!opened) return
      state.patch({ networkDraft: emptyNetworkDraft(), editorTitle: 'Add a network' })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'wifi-network-editor' })
      if (!opened) return
      state.patch({ loadingNetwork: true })
      feedback.clearError()
      try {
        const network = await getWifiNetwork(id)
        state.patch({ networkDraft: draftFrom(network), editorTitle: 'Edit network' })
      } catch (error) {
        modal.close('wifi-network-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingNetwork: false })
      }
    },
    closeEditor,
    setDraft(networkDraft: WifiNetworkInput) {
      state.patch({ networkDraft })
    },
    async save() {
      const draft = state.value().networkDraft
      state.patch({ savingNetwork: true })
      feedback.clearError()
      try {
        const result = await saveWifiNetwork(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Network updated' : 'Network saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingNetwork: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-wifi-network', networkId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-wifi-network')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteWifiNetwork(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-wifi-network')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Network deleted', `${candidate.title} was removed from your vault.`)
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
        networkDraft: emptyNetworkDraft(),
        editorTitle: 'Add a network',
        savingNetwork: false,
        loadingNetwork: false,
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type WifiNetworkController = ReturnType<typeof createWifiNetworkController>

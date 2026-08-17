import type { AppStores } from '../stores/app-stores'
import type { Card, CardInput, LegacyField } from '../types'
import { deleteCard, getCard, recordDiagnostic, saveCard } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

function emptyCardDraft(): CardInput {
  return { title: '', cardholderName: '', number: '', expiryMonth: '', expiryYear: '', securityCode: '', brand: '', notes: '', tags: [] }
}

function draftFrom(card: Card): CardInput {
  const { id, title, cardholderName, number, expiryMonth, expiryYear, securityCode, brand, notes, tags } = card
  return { id, title, cardholderName, number, expiryMonth, expiryYear, securityCode, brand, notes, tags }
}

interface CardControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createCardController({ stores, feedback, modal }: CardControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    cardDraft: emptyCardDraft(),
    editorTitle: 'Add a card',
    savingCard: false,
    loadingCard: false,
    legacyFields: [] as LegacyField[],
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('card-editor')
    state.patch({ cardDraft: emptyCardDraft(), legacyFields: [] })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'card-editor' })
      if (!opened) return
      state.patch({ cardDraft: emptyCardDraft(), editorTitle: 'Add a card', legacyFields: [] })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'card-editor' })
      if (!opened) return
      state.patch({ loadingCard: true })
      feedback.clearError()
      try {
        const card = await getCard(id)
        state.patch({ cardDraft: draftFrom(card), editorTitle: 'Edit card', legacyFields: card.legacyFields ?? [] })
      } catch (error) {
        modal.close('card-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingCard: false })
      }
    },
    closeEditor,
    setDraft(cardDraft: CardInput) {
      state.patch({ cardDraft })
    },
    async save() {
      const draft = state.value().cardDraft
      state.patch({ savingCard: true })
      feedback.clearError()
      try {
        const result = await saveCard(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Card updated' : 'Card saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingCard: false })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-card', cardId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-card')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteCard(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-card')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Card deleted', `${candidate.title} was removed from your vault.`)
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
        cardDraft: emptyCardDraft(),
        editorTitle: 'Add a card',
        savingCard: false,
        loadingCard: false,
        legacyFields: [],
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type CardController = ReturnType<typeof createCardController>

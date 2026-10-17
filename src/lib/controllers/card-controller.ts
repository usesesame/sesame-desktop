import { keptSecretKeys } from '../kept-secrets'
import type { Card, CardInput, SecretView } from '../types'
import { deleteCard, getCard, saveCard } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyCardDraft(): CardInput {
  return { title: '', cardholderName: '', number: '', expiryMonth: '', expiryYear: '', securityCode: '', brand: '', notes: '', tags: [], keptSecrets: [] }
}

function draftFrom(card: SecretView<Card>): CardInput {
  const { id, title, cardholderName, number, expiryMonth, expiryYear, securityCode, brand, notes, tags } = card
  return { id, title, cardholderName, number, expiryMonth, expiryYear, securityCode, brand, notes, tags: tags ?? [], keptSecrets: keptSecretKeys(card) }
}

export function createCardController(options: RecordControllerOptions) {
  return createRecordController<Card, CardInput>(options, {
    editorModal: { kind: 'card-editor' },
    deleteModalKind: 'delete-card',
    deleteModal: (id) => ({ kind: 'delete-card', cardId: id }),
    emptyDraft: emptyCardDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getCard, save: saveCard, delete: deleteCard },
    copy: {
      addTitle: 'Add a card',
      editTitle: 'Edit card',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Card saved' : 'Card updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Card deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type CardController = ReturnType<typeof createCardController>

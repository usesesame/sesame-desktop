import type { Identity, IdentityInput } from '../types'
import { deleteIdentity, getIdentity, saveIdentity } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyIdentityDraft(): IdentityInput {
  return {
    label: '', tags: [], fullName: '', email: '', phone: '',
    addressLine1: '', addressLine2: '', city: '', region: '', postalCode: '', country: '',
  }
}

function draftFrom(identity: Identity): IdentityInput {
  const { id, label, tags, fullName, email, phone, addressLine1, addressLine2, city, region, postalCode, country } = identity
  return { id, label, tags: tags ?? [], fullName, email, phone, addressLine1, addressLine2, city, region, postalCode, country }
}

export function createIdentityController(options: RecordControllerOptions) {
  return createRecordController<Identity, IdentityInput>(options, {
    editorModal: { kind: 'identity-editor' },
    deleteModalKind: 'delete-identity',
    deleteModal: (id) => ({ kind: 'delete-identity', identityId: id }),
    emptyDraft: emptyIdentityDraft,
    draftFrom,
    draftTitle: (draft) => draft.label.trim(),
    api: { get: getIdentity, save: saveIdentity, delete: deleteIdentity },
    copy: {
      addTitle: 'Add an identity',
      editTitle: 'Edit identity',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Identity saved' : 'Identity updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Identity deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type IdentityController = ReturnType<typeof createIdentityController>

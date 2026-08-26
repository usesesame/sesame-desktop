import type { CustomRecord, CustomRecordInput } from '../types'
import { deleteCustomRecord, getCustomRecord, saveCustomRecord } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyRecordDraft(): CustomRecordInput {
  return { title: '', fields: [], notes: '', tags: [] }
}

function draftFrom(record: CustomRecord): CustomRecordInput {
  const { id, title, fields, notes, tags } = record
  return { id, title, fields, notes, tags: tags ?? [] }
}

export function createCustomRecordController(options: RecordControllerOptions) {
  return createRecordController<CustomRecord, CustomRecordInput>(options, {
    editorModal: { kind: 'custom-record-editor' },
    deleteModalKind: 'delete-custom-record',
    deleteModal: (id) => ({ kind: 'delete-custom-record', recordId: id }),
    emptyDraft: emptyRecordDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getCustomRecord, save: saveCustomRecord, delete: deleteCustomRecord },
    copy: {
      addTitle: 'Add a record',
      editTitle: 'Edit record',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Record saved' : 'Record updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Record deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type CustomRecordController = ReturnType<typeof createCustomRecordController>

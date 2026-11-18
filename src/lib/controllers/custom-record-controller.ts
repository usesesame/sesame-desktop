import type { CustomRecord, CustomRecordInput, SecretView } from '../types'
import { draftFields, fieldsInput, type DraftField } from '../kept-secrets'
import { deleteCustomRecord, getCustomRecord, saveCustomRecord } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyRecordDraft(): CustomRecordInput {
  return { title: '', fields: [], notes: '', tags: [], keptSecrets: [] }
}

export type { DraftField }

function draftFrom(record: SecretView<CustomRecord>): CustomRecordInput {
  const { id, title, fields, notes, tags } = record
  return { id, title, fields: draftFields(fields, record.secretFields), notes, tags: tags ?? [], keptSecrets: [] }
}

function inputFrom(draft: CustomRecordInput): CustomRecordInput {
  return { ...draft, ...fieldsInput(draft.fields as DraftField[]) }
}

export function createCustomRecordController(options: RecordControllerOptions) {
  return createRecordController<CustomRecord, CustomRecordInput>(options, {
    editorModal: { kind: 'custom-record-editor' },
    deleteModalKind: 'delete-custom-record',
    deleteModal: (id) => ({ kind: 'delete-custom-record', recordId: id }),
    emptyDraft: emptyRecordDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getCustomRecord, save: (draft) => saveCustomRecord(inputFrom(draft)), delete: deleteCustomRecord },
    copy: {
      addTitle: 'Add a record',
      editTitle: 'Edit record',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Record saved' : 'Record updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Record deleted', body: `${title} is in Trash for 30 days.` }),
    },
  })
}

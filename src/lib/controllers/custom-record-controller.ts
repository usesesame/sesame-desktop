import type { CustomFieldEntry, CustomRecord, CustomRecordInput, SecretView } from '../types'
import { deleteCustomRecord, getCustomRecord, saveCustomRecord } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyRecordDraft(): CustomRecordInput {
  return { title: '', fields: [], notes: '', tags: [], keptSecrets: [] }
}

export type DraftField = CustomFieldEntry & { keptFrom?: number }

function draftFrom(record: SecretView<CustomRecord>): CustomRecordInput {
  const { id, title, fields, notes, tags } = record
  const rows: DraftField[] = fields.map((field, index) => record.secretFields.includes(`field:${index}`) ? { ...field, value: '', keptFrom: index } : field)
  return { id, title, fields: rows, notes, tags: tags ?? [], keptSecrets: [] }
}

function inputFrom(draft: CustomRecordInput): CustomRecordInput {
  const keptSecrets: string[] = []
  const fields = (draft.fields as DraftField[]).map((row, index) => {
    const { keptFrom, ...field } = row
    if (keptFrom !== undefined && field.kind === 'secret' && !field.value) keptSecrets.push(`field:${index}<-${keptFrom}`)
    return field
  })
  return { ...draft, fields, keptSecrets }
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
      deletedNotice: (title) => ({ title: 'Record deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type CustomRecordController = ReturnType<typeof createCustomRecordController>

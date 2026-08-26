import type { SecureNote, SecureNoteInput } from '../types'
import { deleteSecureNote, getSecureNote, saveSecureNote } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyNoteDraft(): SecureNoteInput {
  return { title: '', content: '', tags: [] }
}

function draftFrom(note: SecureNote): SecureNoteInput {
  const { id, title, content, tags } = note
  return { id, title, content, tags: tags ?? [] }
}

export function createSecureNoteController(options: RecordControllerOptions) {
  return createRecordController<SecureNote, SecureNoteInput>(options, {
    editorModal: { kind: 'secure-note-editor' },
    deleteModalKind: 'delete-secure-note',
    deleteModal: (id) => ({ kind: 'delete-secure-note', noteId: id }),
    emptyDraft: emptyNoteDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getSecureNote, save: saveSecureNote, delete: deleteSecureNote },
    copy: {
      addTitle: 'Add a note',
      editTitle: 'Edit note',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Note saved' : 'Note updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Note deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type SecureNoteController = ReturnType<typeof createSecureNoteController>

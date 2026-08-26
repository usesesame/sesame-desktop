import type { SshKey, SshKeyInput } from '../types'
import { deleteSshKey, getSshKey, saveSshKey } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyKeyDraft(): SshKeyInput {
  return { title: '', keyType: '', privateKey: '', publicKey: '', passphrase: '', notes: '', tags: [] }
}

function draftFrom(key: SshKey): SshKeyInput {
  const { id, title, keyType, privateKey, publicKey, passphrase, notes, tags } = key
  return { id, title, keyType, privateKey, publicKey, passphrase, notes, tags: tags ?? [] }
}

export function createSshKeyController(options: RecordControllerOptions) {
  return createRecordController<SshKey, SshKeyInput>(options, {
    editorModal: { kind: 'ssh-key-editor' },
    deleteModalKind: 'delete-ssh-key',
    deleteModal: (id) => ({ kind: 'delete-ssh-key', keyId: id }),
    emptyDraft: emptyKeyDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getSshKey, save: saveSshKey, delete: deleteSshKey },
    copy: {
      addTitle: 'Add a key',
      editTitle: 'Edit key',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Key saved' : 'Key updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Key deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type SshKeyController = ReturnType<typeof createSshKeyController>

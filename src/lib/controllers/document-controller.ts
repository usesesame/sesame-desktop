import type { Attachment, DocumentMetadata, DocumentMetadataInput } from '../types'
import { addDocumentAttachment, deleteDocument, getDocument, removeDocumentAttachment, saveDocument } from '../vault'
import { controllerStore } from './controller-store'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyDocumentDraft(): DocumentMetadataInput {
  return { title: '', documentType: '', documentNumber: '', issuingAuthority: '', issueDate: '', expiryDate: '', notes: '', tags: [] }
}

function draftFrom(document: DocumentMetadata): DocumentMetadataInput {
  const { id, title, documentType, documentNumber, issuingAuthority, issueDate, expiryDate, notes, tags } = document
  return { id, title, documentType, documentNumber, issuingAuthority, issueDate, expiryDate, notes, tags: tags ?? [] }
}

// URL-safe no-pad alphabet; Rust's decoder expects exactly this.
const BASE64_URL_SAFE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

function bytesToBase64Url(bytes: Uint8Array): string {
  let result = ''
  let index = 0
  for (; index + 2 < bytes.length; index += 3) {
    const chunk = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2]
    result +=
      BASE64_URL_SAFE_CHARS[(chunk >> 18) & 63] +
      BASE64_URL_SAFE_CHARS[(chunk >> 12) & 63] +
      BASE64_URL_SAFE_CHARS[(chunk >> 6) & 63] +
      BASE64_URL_SAFE_CHARS[chunk & 63]
  }
  const remaining = bytes.length - index
  if (remaining === 1) {
    const chunk = bytes[index] << 16
    result += BASE64_URL_SAFE_CHARS[(chunk >> 18) & 63] + BASE64_URL_SAFE_CHARS[(chunk >> 12) & 63]
  } else if (remaining === 2) {
    const chunk = (bytes[index] << 16) | (bytes[index + 1] << 8)
    result +=
      BASE64_URL_SAFE_CHARS[(chunk >> 18) & 63] +
      BASE64_URL_SAFE_CHARS[(chunk >> 12) & 63] +
      BASE64_URL_SAFE_CHARS[(chunk >> 6) & 63]
  }
  return result
}

async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  return bytesToBase64Url(bytes)
}

/// Attachments live outside RecordConfig's shape: they need their own store and
/// a fetch that runs as a side effect of the base controller's own get, so a
/// single load populates both the draft and the attachment list.
export function createDocumentController(options: RecordControllerOptions) {
  const { stores, modal } = options
  const attachmentState = controllerStore({
    documentAttachments: [] as Attachment[],
    uploadingAttachment: false,
    attachmentError: '',
    removingAttachmentId: null as string | null,
  })

  async function fetchDocument(id: string): Promise<DocumentMetadata> {
    const document = await getDocument(id)
    attachmentState.patch({ documentAttachments: document.attachments ?? [] })
    return document
  }

  const base = createRecordController<DocumentMetadata, DocumentMetadataInput>(options, {
    editorModal: { kind: 'document-editor' },
    deleteModalKind: 'delete-document',
    deleteModal: (id) => ({ kind: 'delete-document', documentId: id }),
    emptyDraft: emptyDocumentDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: fetchDocument, save: saveDocument, delete: deleteDocument },
    copy: {
      addTitle: 'Add a document',
      editTitle: 'Edit document',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Document saved' : 'Document updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Document deleted', body: `${title} was removed from your vault.` }),
    },
  })

  return {
    ...base,
    attachmentState,
    openNew() {
      base.openNew()
      if (modal.state.value().active?.kind === 'document-editor') {
        attachmentState.patch({ documentAttachments: [], attachmentError: '' })
      }
    },
    closeEditor() {
      base.closeEditor()
      attachmentState.patch({ documentAttachments: [], attachmentError: '' })
    },
    async addAttachment(file: File) {
      const documentId = base.state.value().draft.id
      if (!documentId) return
      attachmentState.patch({ uploadingAttachment: true, attachmentError: '' })
      try {
        const data = await fileToBase64(file)
        const result = await addDocumentAttachment(documentId, file.name, file.type, data)
        stores.vault.patch({ snapshot: result.snapshot })
        await fetchDocument(documentId)
      } catch (error) {
        attachmentState.patch({ attachmentError: error instanceof Error ? error.message : 'That file could not be attached.' })
      } finally {
        attachmentState.patch({ uploadingAttachment: false })
      }
    },
    async removeAttachment(attachmentId: string) {
      const documentId = base.state.value().draft.id
      if (!documentId) return
      attachmentState.patch({ removingAttachmentId: attachmentId, attachmentError: '' })
      try {
        const result = await removeDocumentAttachment(documentId, attachmentId)
        stores.vault.patch({ snapshot: result.snapshot })
        await fetchDocument(documentId)
      } catch (error) {
        attachmentState.patch({ attachmentError: error instanceof Error ? error.message : 'That attachment could not be removed.' })
      } finally {
        attachmentState.patch({ removingAttachmentId: null })
      }
    },
    clearSecrets() {
      base.clearSecrets()
      attachmentState.set({ documentAttachments: [], uploadingAttachment: false, attachmentError: '', removingAttachmentId: null })
    },
  }
}

export type DocumentController = ReturnType<typeof createDocumentController>

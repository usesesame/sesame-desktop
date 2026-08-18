import type { AppStores } from '../stores/app-stores'
import type { Attachment, DocumentMetadata, DocumentMetadataInput } from '../types'
import { addDocumentAttachment, deleteDocument, getDocument, recordDiagnostic, removeDocumentAttachment, saveDocument } from '../vault'
import { controllerStore } from './controller-store'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

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

interface DocumentControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
}

/// Full records fetch one at a time; the draft must not survive a lock.
export function createDocumentController({ stores, feedback, modal }: DocumentControllerOptions) {
  const { vault } = stores
  const state = controllerStore({
    documentDraft: emptyDocumentDraft(),
    editorTitle: 'Add a document',
    savingDocument: false,
    loadingDocument: false,
    documentAttachments: [] as Attachment[],
    uploadingAttachment: false,
    attachmentError: '',
    removingAttachmentId: null as string | null,
    deleteCandidate: null as { id: string; title: string } | null,
    deleteWorking: false,
  })

  function closeEditor() {
    modal.close('document-editor')
    state.patch({ documentDraft: emptyDocumentDraft(), documentAttachments: [], attachmentError: '' })
  }

  /// Snapshot never carries attachment bytes; refetch the full record instead.
  async function refreshAttachments(id: string) {
    const document = await getDocument(id)
    state.patch({ documentAttachments: document.attachments ?? [] })
  }

  return {
    state,
    openNew() {
      const opened = modal.open({ kind: 'document-editor' })
      if (!opened) return
      state.patch({ documentDraft: emptyDocumentDraft(), documentAttachments: [], editorTitle: 'Add a document' })
      feedback.clearError()
    },
    async openEditor(id: string) {
      const opened = modal.open({ kind: 'document-editor' })
      if (!opened) return
      state.patch({ loadingDocument: true })
      feedback.clearError()
      try {
        const document = await getDocument(id)
        state.patch({ documentDraft: draftFrom(document), documentAttachments: document.attachments ?? [], editorTitle: 'Edit document' })
      } catch (error) {
        modal.close('document-editor')
        feedback.setError(error)
      } finally {
        state.patch({ loadingDocument: false })
      }
    },
    closeEditor,
    setDraft(documentDraft: DocumentMetadataInput) {
      state.patch({ documentDraft })
    },
    async save() {
      const draft = state.value().documentDraft
      state.patch({ savingDocument: true })
      feedback.clearError()
      try {
        const result = await saveDocument(draft)
        vault.patch({ snapshot: result.snapshot })
        closeEditor()
        feedback.showNotice(draft.id ? 'Document updated' : 'Document saved', `${draft.title.trim()} is stored in your vault.`)
      } catch (error) {
        feedback.setError(error)
      } finally {
        state.patch({ savingDocument: false })
      }
    },
    async addAttachment(file: File) {
      const documentId = state.value().documentDraft.id
      if (!documentId) return
      state.patch({ uploadingAttachment: true, attachmentError: '' })
      try {
        const data = await fileToBase64(file)
        const result = await addDocumentAttachment(documentId, file.name, file.type, data)
        vault.patch({ snapshot: result.snapshot })
        await refreshAttachments(documentId)
      } catch (error) {
        state.patch({ attachmentError: error instanceof Error ? error.message : 'That file could not be attached.' })
      } finally {
        state.patch({ uploadingAttachment: false })
      }
    },
    async removeAttachment(attachmentId: string) {
      const documentId = state.value().documentDraft.id
      if (!documentId) return
      state.patch({ removingAttachmentId: attachmentId, attachmentError: '' })
      try {
        const result = await removeDocumentAttachment(documentId, attachmentId)
        vault.patch({ snapshot: result.snapshot })
        await refreshAttachments(documentId)
      } catch (error) {
        state.patch({ attachmentError: error instanceof Error ? error.message : 'That attachment could not be removed.' })
      } finally {
        state.patch({ removingAttachmentId: null })
      }
    },
    requestDelete(id: string, title: string) {
      const opened = modal.open({ kind: 'delete-document', documentId: id })
      if (opened) state.patch({ deleteCandidate: { id, title } })
    },
    cancelDelete() {
      modal.close('delete-document')
      state.patch({ deleteCandidate: null })
    },
    async confirmDelete() {
      const candidate = state.value().deleteCandidate
      if (!candidate) return
      state.patch({ deleteWorking: true })
      feedback.clearError()
      try {
        const result = await deleteDocument(candidate.id)
        vault.patch({ snapshot: result.snapshot })
        modal.close('delete-document')
        state.patch({ deleteCandidate: null })
        feedback.showNotice('Document deleted', `${candidate.title} was removed from your vault.`)
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
        documentDraft: emptyDocumentDraft(),
        editorTitle: 'Add a document',
        savingDocument: false,
        loadingDocument: false,
        documentAttachments: [],
        uploadingAttachment: false,
        attachmentError: '',
        removingAttachmentId: null,
        deleteCandidate: null,
        deleteWorking: false,
      })
    },
  }
}

export type DocumentController = ReturnType<typeof createDocumentController>

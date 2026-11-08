/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import DocumentEditor from './DocumentEditor.svelte'
import type { Attachment, DocumentMetadataInput } from '../types'

afterEach(() => cleanup())

function attachment(id: string, filename: string): Attachment {
  return { id, filename, contentType: 'application/pdf', size: 2048, data: '' }
}

function editor(savingAttachmentId: string | null) {
  const onSaveAttachment = vi.fn()
  render(DocumentEditor, {
    documentDraft: {
      id: 'fictional-document-01',
      title: 'Fictional passport',
      documentType: '',
      documentNumber: '',
      issuingAuthority: '',
      issueDate: '',
      expiryDate: '',
      notes: '',
      tags: [],
      keptSecrets: [],
    } satisfies DocumentMetadataInput,
    attachments: [attachment('fictional-attachment-01', 'front.pdf'), attachment('fictional-attachment-02', 'back.pdf')],
    savingAttachmentId,
    onSubmit: vi.fn(),
    onClose: vi.fn(),
    onAddAttachment: vi.fn(),
    onSaveAttachment,
    onRemoveAttachment: vi.fn(),
  })
  return onSaveAttachment
}

test('every attachment save button is disabled while one attachment is saving', () => {
  editor('fictional-attachment-01')
  const front = screen.getByTitle('Save front.pdf') as HTMLButtonElement
  const back = screen.getByTitle('Save back.pdf') as HTMLButtonElement
  expect(front.disabled).toBe(true)
  expect(back.disabled).toBe(true)
  expect(front.getAttribute('aria-busy')).toBe('true')
  expect(back.getAttribute('aria-busy')).toBe('false')
})

test('an attachment save sends only the attachment id', () => {
  const onSaveAttachment = editor(null)
  const back = screen.getByTitle('Save back.pdf') as HTMLButtonElement
  expect(back.disabled).toBe(false)
  back.click()
  expect(onSaveAttachment).toHaveBeenCalledWith('fictional-attachment-02')
})

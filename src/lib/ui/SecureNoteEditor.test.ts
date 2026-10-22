/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import SecureNoteEditor from './SecureNoteEditor.svelte'

afterEach(cleanup)

function renderEditor(draft: Record<string, unknown>, overrides: Record<string, unknown> = {}) {
  const props = {
    noteDraft: { title: 'Fictional note', content: '', locked: false, tags: [], keptSecrets: [], ...draft },
    editorTitle: 'Edit note',
    savingNote: false,
    loadingNote: false,
    legacyFields: [],
    onDraftChange: vi.fn(),
    onSubmit: vi.fn(),
    onClose: vi.fn(),
    ...overrides,
  }
  render(SecureNoteEditor, { props } as never)
  return props
}

test('a new note can be locked from the editor', async () => {
  const props = renderEditor({})

  const lock = screen.getByRole('checkbox', { name: /master password to open this note/i }) as HTMLInputElement
  expect(lock.checked).toBe(false)
  expect(lock.disabled).toBe(false)
  await fireEvent.click(lock)

  expect(props.onDraftChange).toHaveBeenLastCalledWith(expect.objectContaining({ locked: true }))
})

test('a stored locked note opens with a blank body and the lock can only be removed on its page', () => {
  renderEditor({ locked: true, keptSecrets: ['content'] })

  expect((screen.getByRole('checkbox', { name: /master password to open this note/i }) as HTMLInputElement).disabled).toBe(true)
  expect((document.querySelector('textarea[name="note-content"]') as HTMLTextAreaElement).value).toBe('')
  expect(screen.getByText(/saved value stays as it is unless you type a new one/i)).toBeTruthy()
  expect(screen.getByText(/Remove the lock on the note's page/i)).toBeTruthy()
})

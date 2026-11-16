/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { DraftField } from '../kept-secrets'
import type { LoginInput } from '../types'
import LoginCustomFields from './LoginCustomFields.svelte'
import LoginEditor from './LoginEditor.svelte'

const vaultApi = vi.hoisted(() => ({
  grantPresence: vi.fn(),
  revealLoginSecret: vi.fn(),
  suggestFieldValues: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  PRESENCE_REQUIRED: 'presenceRequired',
  ...vaultApi,
}))

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  vi.clearAllMocks()
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

function loginDraft(overrides: Partial<LoginInput> = {}): LoginInput {
  return {
    id: 'login-a',
    title: 'Northwind',
    url: 'https://northwind.example.test',
    urls: [],
    tags: [],
    username: 'alpha@example.test',
    email: '',
    password: '',
    folder: '',
    totp: undefined,
    keepBackupCodes: false,
    backupCodes: [],
    recoveryEmail: '',
    recoveryPhone: '',
    recoveryNotApplicable: false,
    notes: '',
    ...overrides,
  }
}

function renderFields(fields: DraftField[]) {
  const onChange = vi.fn()
  const result = render(LoginCustomFields, { props: { fields, onChange } } as never)
  const latest = (): DraftField[] => onChange.mock.lastCall?.[0] ?? fields
  const update = async (next: DraftField[]) => {
    await result.rerender({ fields: next, onChange })
  }
  return { onChange, latest, update }
}

test('the login editor shows the custom fields section below the notes', () => {
  render(LoginEditor, {
    props: { loginDraft: loginDraft(), onSubmit: vi.fn(), onClose: vi.fn(), onDelete: vi.fn() },
    context: new Map([[APP_STORES, createAppStores()]]),
  } as never)

  const notes = document.querySelector('textarea[name="login-notes"]')!
  const section = screen.getByRole('region', { name: 'Custom fields' })
  expect(notes.compareDocumentPosition(section) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Add field' })).toBeTruthy()
})

test('adding a field gives it a name, a value and a hidden switch', async () => {
  const fields = renderFields([])

  await fireEvent.click(screen.getByRole('button', { name: 'Add field' }))
  expect(fields.latest()).toEqual([{ label: '', value: '', kind: 'text' }])
  await fields.update(fields.latest())
  await fireEvent.input(screen.getByRole('textbox', { name: 'Field 1 name' }), { target: { value: 'Security answer' } })
  await fields.update(fields.latest())
  await fireEvent.input(screen.getByRole('textbox', { name: 'Field 1 value' }), { target: { value: 'fictional-answer' } })
  await fields.update(fields.latest())
  const hidden = screen.getByRole('switch', { name: 'Field 1 hidden' })
  expect(hidden.getAttribute('aria-checked')).toBe('false')
  await fireEvent.click(hidden)
  await fields.update(fields.latest())

  expect(screen.getByRole('switch', { name: 'Field 1 hidden' }).getAttribute('aria-checked')).toBe('true')
  expect((document.querySelector('input[aria-label="Field 1 value"]') as HTMLInputElement).type).toBe('password')
  expect(fields.latest()).toEqual([{ label: 'Security answer', value: 'fictional-answer', kind: 'secret' }])
})

test('a saved hidden value is never in the editor and stays unless removed', async () => {
  const fields = renderFields([{ label: 'Security answer', value: '', kind: 'secret', keptFrom: 0 }])

  const value = document.querySelector('input[aria-label="Field 1 value"]') as HTMLInputElement
  expect(value.value).toBe('')
  expect(value.type).toBe('password')
  expect(value.placeholder).toBe('Saved value kept')
  await fireEvent.click(screen.getByRole('button', { name: 'Remove saved value' }))
  expect(fields.latest()).toEqual([{ label: 'Security answer', value: '', kind: 'secret', keptFrom: undefined }])
  await fields.update(fields.latest())
  expect(screen.queryByRole('button', { name: 'Remove saved value' })).toBeNull()
})

test('turning off hidden on a kept value warns that the value goes', async () => {
  const fields = renderFields([{ label: 'Security answer', value: '', kind: 'secret', keptFrom: 0 }])

  await fireEvent.click(screen.getByRole('switch', { name: 'Field 1 hidden' }))
  await fields.update(fields.latest())

  expect(screen.getByText(/The saved hidden value is removed when you save/)).toBeTruthy()
})

test('removing a field drops it and every remove button has a matching title', async () => {
  const fields = renderFields([
    { label: 'Member number', value: 'fictional-42', kind: 'text' },
    { label: 'Security answer', value: '', kind: 'secret', keptFrom: 1 },
  ])

  for (const button of screen.getAllByRole('button', { name: /^Remove field/ })) {
    expect(button.getAttribute('title')).toBe(button.getAttribute('aria-label'))
  }
  await fireEvent.click(screen.getByRole('button', { name: 'Remove field 1' }))

  expect(fields.latest()).toEqual([{ label: 'Security answer', value: '', kind: 'secret', keptFrom: 1 }])
})

/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { LoginInput } from '../types'
import LoginEditor from './LoginEditor.svelte'

vi.mock('../vault', () => ({
  previewMode: false,
  PRESENCE_REQUIRED: 'presenceRequired',
  grantPresence: vi.fn(),
  revealLoginSecret: vi.fn(),
  suggestFieldValues: vi.fn(),
}))

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

function draft(overrides: Partial<LoginInput> = {}): LoginInput {
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
    keepBackupCodes: false,
    backupCodes: [],
    recoveryEmail: '',
    recoveryPhone: '',
    recoveryNotApplicable: false,
    notes: '',
    ...overrides,
  }
}

function renderEditor(loginDraft: LoginInput, onSubmit = vi.fn()) {
  render(LoginEditor, {
    props: { loginDraft, onSubmit, onClose: vi.fn(), onDelete: vi.fn() },
    context: new Map([[APP_STORES, createAppStores()]]),
  } as never)
  return onSubmit
}

test('a login without a rule shows the exact rule and what it does', () => {
  renderEditor(draft())

  expect(screen.getByRole('button', { name: 'Browser filling: This address only' })).toBeTruthy()
  expect(screen.getByText('Sesame offers this login only on northwind.example.test and its www form.')).toBeTruthy()
})

test('choosing a rule changes the line under it', async () => {
  renderEditor(draft({ matchRule: 'site' }))
  expect(screen.getByText(/other addresses under the same site as northwind\.example\.test/)).toBeTruthy()

  await fireEvent.click(screen.getByRole('button', { name: 'Browser filling: Whole site' }))
  await fireEvent.click(screen.getByRole('option', { name: 'Never fill' }))

  expect(screen.getByRole('button', { name: 'Browser filling: Never fill' })).toBeTruthy()
  expect(screen.getByText('Sesame never offers this login in the browser. You can still copy it from here.')).toBeTruthy()
})

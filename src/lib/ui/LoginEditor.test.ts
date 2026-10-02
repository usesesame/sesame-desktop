/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { LoginInput } from '../types'
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
    backupCodes: [],
    recoveryEmail: '',
    recoveryPhone: '',
    recoveryNotApplicable: false,
    notes: '',
    ...overrides,
  }
}

function renderEditor(overrides: Record<string, unknown> = {}) {
  return render(LoginEditor, {
    props: {
      loginDraft: loginDraft(),
      onSubmit: vi.fn(),
      onClose: vi.fn(),
      onDelete: vi.fn(),
      ...overrides,
    },
    context: new Map([[APP_STORES, createAppStores()]]),
  } as never)
}

function passwordInput(): HTMLInputElement {
  return document.querySelector<HTMLInputElement>('input[name="login-password"]')!
}

test('showing a saved password asks the vault again and hiding clears the field', async () => {
  vaultApi.revealLoginSecret
    .mockResolvedValueOnce('fictional-alpha-secret')
    .mockResolvedValueOnce('fictional-alpha-rotated')
  renderEditor()
  await Promise.resolve()
  const password = passwordInput()

  expect(password.value).toBe('')

  await fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  await vi.waitFor(() => expect(password.value).toBe('fictional-alpha-secret'))
  expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(1)
  expect(vaultApi.revealLoginSecret).toHaveBeenLastCalledWith('login-a')

  await fireEvent.click(screen.getByRole('button', { name: 'Hide password' }))
  expect(password.value).toBe('')
  expect(password.type).toBe('password')

  await fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  await vi.waitFor(() => expect(password.value).toBe('fictional-alpha-rotated'))
  expect(vaultApi.revealLoginSecret).toHaveBeenCalledTimes(2)
  expect(vaultApi.revealLoginSecret).toHaveBeenLastCalledWith('login-a')
})

test('showing and hiding a typed replacement preserves the value that will be saved', async () => {
  renderEditor()
  const password = passwordInput()
  await fireEvent.input(password, { target: { value: 'fictional-replacement' } })
  await fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  expect(password.value).toBe('fictional-replacement')
  expect(password.type).toBe('text')
  expect(vaultApi.revealLoginSecret).not.toHaveBeenCalled()

  await fireEvent.click(screen.getByRole('button', { name: 'Hide password' }))
  expect(password.value).toBe('')
  await fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  expect(password.value).toBe('fictional-replacement')
  expect(vaultApi.revealLoginSecret).not.toHaveBeenCalled()
})

test('showing a generated replacement preserves the generated draft', async () => {
  renderEditor()
  await fireEvent.click(screen.getByRole('button', { name: 'Generate a password' }))
  const generated = passwordInput().value
  expect(generated.length).toBeGreaterThan(0)
  await fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  expect(passwordInput().value).toBe(generated)
  await fireEvent.click(screen.getByRole('button', { name: 'Hide password' }))
  expect(passwordInput().value).toBe('')
  await fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  expect(passwordInput().value).toBe(generated)
  expect(vaultApi.revealLoginSecret).not.toHaveBeenCalled()
})

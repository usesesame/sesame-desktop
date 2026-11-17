/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { LoginInput } from '../types'
import { clearEmailAliases, emailAliases, refreshEmailAliases } from '../email-aliases'
import LoginEditor from './LoginEditor.svelte'

const vault = vi.hoisted(() => ({
  createEmailAlias: vi.fn(),
  getEmailAliasSettings: vi.fn(),
}))

vi.mock('../vault', () => ({
  previewMode: false,
  PRESENCE_REQUIRED: 'presenceRequired',
  grantPresence: vi.fn(),
  revealLoginSecret: vi.fn(),
  suggestFieldValues: vi.fn(),
  createEmailAlias: vault.createEmailAlias,
  getEmailAliasSettings: vault.getEmailAliasSettings,
  saveEmailAliasSettings: vi.fn(),
  removeEmailAliasSettings: vi.fn(),
}))

afterEach(() => {
  cleanup()
  clearEmailAliases()
  document.body.replaceChildren()
  vi.clearAllMocks()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

function draft(overrides: Partial<LoginInput> = {}): LoginInput {
  return {
    title: 'Northwind',
    url: 'https://northwind.example.test/login',
    urls: [],
    tags: [],
    username: '',
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

function renderEditor(loginDraft: LoginInput) {
  render(LoginEditor, {
    props: { loginDraft, onSubmit: vi.fn(), onClose: vi.fn(), onDelete: vi.fn() },
    context: new Map([[APP_STORES, createAppStores()]]),
  } as never)
}

test('the action stays hidden while aliases are off', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  renderEditor(draft())
  await waitFor(() => expect(vault.getEmailAliasSettings).toHaveBeenCalled())
  expect(screen.queryByRole('button', { name: 'Create alias' })).toBeNull()
})

test('a new alias goes into the email field and the site address goes to the backend to decide on', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  vault.createEmailAlias.mockResolvedValue('quiet.harbor@anonaddy.me')
  renderEditor(draft())

  await fireEvent.click(await screen.findByRole('button', { name: 'Create alias' }))

  await waitFor(() => expect((screen.getByLabelText(/^Email/) as HTMLInputElement).value).toBe('quiet.harbor@anonaddy.me'))
  expect(vault.createEmailAlias).toHaveBeenCalledWith('https://northwind.example.test/login')
  expect(screen.getByRole('status').textContent).toBe('addy.io made a new alias. Save the login to keep it.')
})

test('a failed request leaves the email field alone and shows the message', async () => {
  emailAliases.set({ service: 'simpleLogin', nameSite: true })
  vault.createEmailAlias.mockRejectedValue(new Error('The alias service did not accept your API token. Paste a new one in Settings.'))
  renderEditor(draft({ email: 'kept@example.test' }))

  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))

  expect((await screen.findByRole('alert')).textContent).toBe('The alias service did not accept your API token. Paste a new one in Settings.')
  expect((screen.getByLabelText(/^Email/) as HTMLInputElement).value).toBe('kept@example.test')
  expect(vault.getEmailAliasSettings).not.toHaveBeenCalled()
})

test('the action follows the vault when it changes while the editor is open', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  renderEditor(draft())
  await screen.findByRole('button', { name: 'Create alias' })

  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  await refreshEmailAliases()
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Create alias' })).toBeNull())

  vault.getEmailAliasSettings.mockResolvedValue({ service: 'simpleLogin', nameSite: false })
  await refreshEmailAliases()
  expect(await screen.findByRole('button', { name: 'Create alias' })).toBeTruthy()
})

test('a refresh that fails keeps what the editor already knew', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  vault.getEmailAliasSettings.mockRejectedValue(new Error('Unlock your vault first.'))
  renderEditor(draft())

  await refreshEmailAliases()

  expect(screen.getByRole('button', { name: 'Create alias' })).toBeTruthy()
})

test('one click asks for one alias and a failure is not retried', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  let fail: (error: Error) => void = () => {}
  vault.createEmailAlias.mockImplementation(() => new Promise((_resolve, reject) => { fail = reject }))
  renderEditor(draft())
  const button = screen.getByRole('button', { name: 'Create alias' })

  await fireEvent.click(button)
  await fireEvent.click(button)
  expect(vault.createEmailAlias).toHaveBeenCalledOnce()

  fail(new Error('Sesame could not reach the alias service. Check your connection and try again.'))
  expect((await screen.findByRole('alert')).textContent).toBe('Sesame could not reach the alias service. Check your connection and try again.')
  await new Promise((resolve) => setTimeout(resolve, 50))
  expect(vault.createEmailAlias).toHaveBeenCalledOnce()
})

test('the note names the service that made the alias even if the setting changes meanwhile', async () => {
  emailAliases.set({ service: 'simpleLogin', nameSite: false })
  let finish: (alias: string) => void = () => {}
  vault.createEmailAlias.mockImplementation(() => new Promise((resolve) => { finish = resolve }))
  renderEditor(draft())

  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  finish('quiet_harbor42@simplelogin.example')

  expect((await screen.findByRole('status')).textContent).toBe('SimpleLogin made a new alias. Save the login to keep it.')
})

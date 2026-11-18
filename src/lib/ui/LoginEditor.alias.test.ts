/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { LoginInput } from '../types'
import { clearEmailAliases, emailAliases, refreshEmailAliases } from '../email-aliases'
import LoginEditor from './LoginEditor.svelte'
import LoginEditorAliasHost from './LoginEditorAliasHost.test.svelte'

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
  const props = { loginDraft, onSubmit: vi.fn(), onClose: vi.fn(), onDelete: vi.fn() }
  render(LoginEditor, {
    props,
    context: new Map([[APP_STORES, createAppStores()]]),
  } as never)
  return props
}

function pendingAlias() {
  let finish: (alias: string) => void = () => {}
  let fail: (error: Error) => void = () => {}
  vault.createEmailAlias.mockImplementation(() => new Promise<string>((resolve, reject) => { finish = resolve; fail = reject }))
  return { finish: (alias: string) => finish(alias), fail: (error: Error) => fail(error) }
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

test('the login cannot be saved while an alias is being made', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  const request = pendingAlias()
  const props = renderEditor(draft())

  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  const save = screen.getByRole('button', { name: 'Save login' }) as HTMLButtonElement
  expect(save.disabled).toBe(true)
  await fireEvent.submit(save.closest('form') as HTMLFormElement)
  expect(props.onSubmit).not.toHaveBeenCalled()

  request.finish('quiet.harbor@anonaddy.me')
  await waitFor(() => expect(save.disabled).toBe(false))
  await fireEvent.submit(save.closest('form') as HTMLFormElement)
  expect(props.onSubmit).toHaveBeenCalledOnce()
})

test('closing an unchanged login while an alias is being made asks first', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  pendingAlias()
  const props = renderEditor(draft())

  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Close login editor' }))

  expect(props.onClose).not.toHaveBeenCalled()
  expect(document.body.textContent).toContain('An alias is still being made. Leaving does not stop it, and the new address will not be saved here.')
  expect(document.body.textContent).toContain('Leave this login?')
  await fireEvent.click(screen.getByRole('button', { name: 'Leave' }))
  expect(props.onClose).toHaveBeenCalledOnce()
})

test('an email typed while the alias was being made is kept and the alias is offered', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  const request = pendingAlias()
  renderEditor(draft())
  const email = screen.getByLabelText(/^Email/) as HTMLInputElement

  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  await fireEvent.input(email, { target: { value: 'typed@example.test' } })
  request.finish('quiet.harbor@anonaddy.me')

  expect((await screen.findByRole('status')).textContent).toBe('addy.io made quiet.harbor@anonaddy.me. You changed the email while it was being made, so Sesame kept what you typed.')
  expect(email.value).toBe('typed@example.test')

  await fireEvent.click(screen.getByRole('button', { name: 'Use the alias' }))
  expect(email.value).toBe('quiet.harbor@anonaddy.me')
  expect(screen.getByRole('status').textContent).toBe('addy.io made a new alias. Save the login to keep it.')
  expect(screen.queryByRole('button', { name: 'Use the alias' })).toBeNull()
})

test('the result of a started request stays visible after aliases are turned off', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  const success = pendingAlias()
  renderEditor(draft())
  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  emailAliases.set({ nameSite: false })
  success.finish('quiet.harbor@anonaddy.me')

  expect((await screen.findByRole('status')).textContent).toBe('addy.io made a new alias. Save the login to keep it.')
  expect((screen.getByLabelText(/^Email/) as HTMLInputElement).value).toBe('quiet.harbor@anonaddy.me')
  expect(screen.queryByRole('button', { name: 'Create alias' })).toBeNull()
  cleanup()

  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  const failure = pendingAlias()
  renderEditor(draft())
  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  emailAliases.set({ nameSite: false })
  failure.fail(new Error('The alias service is having trouble. Try again later.'))

  expect((await screen.findByRole('alert')).textContent).toBe('The alias service is having trouble. Try again later.')
})

test('an alias that arrives after the editor was left never reaches the next login', async () => {
  emailAliases.set({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  const request = pendingAlias()
  const onSubmit = vi.fn()
  const host = render(LoginEditorAliasHost, {
    props: { draft: draft({ title: 'Northwind' }), onSubmit },
    context: new Map([[APP_STORES, createAppStores()]]),
  } as never).component as unknown as { reopen: (next: LoginInput) => void, current: () => LoginInput }

  await fireEvent.click(screen.getByRole('button', { name: 'Create alias' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Close login editor' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Leave' }))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Leave' })).toBeNull())

  host.reopen(draft({ title: 'Contoso', url: 'https://contoso.example.test/' }))
  await screen.findByRole('button', { name: 'Create alias' })
  request.finish('quiet.harbor@anonaddy.me')
  await new Promise((resolve) => setTimeout(resolve, 20))

  expect(host.current().title).toBe('Contoso')
  expect(host.current().email).toBe('')
  expect((screen.getByLabelText(/^Email/) as HTMLInputElement).value).toBe('')
  expect(screen.queryByRole('status')).toBeNull()
  await fireEvent.submit(screen.getByRole('button', { name: 'Save login' }).closest('form') as HTMLFormElement)
  expect(onSubmit).toHaveBeenCalledOnce()
  expect(host.current().email).toBe('')
})

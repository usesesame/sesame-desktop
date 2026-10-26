/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { LoginInput, VaultEntrySummary, VaultSnapshot } from '../types'
import LoginEditor from './LoginEditor.svelte'

const vaultApi = vi.hoisted(() => ({
  grantPresence: vi.fn(),
  revealLoginSecret: vi.fn(),
  suggestFieldValues: vi.fn(),
}))

vi.mock('../vault', () => ({ previewMode: false, PRESENCE_REQUIRED: 'presenceRequired', ...vaultApi }))

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  vi.clearAllMocks()
  vaultApi.suggestFieldValues.mockResolvedValue([])
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

function summary(id: string, overrides: Partial<VaultEntrySummary> = {}): VaultEntrySummary {
  return { id, title: id, site: 'example.test', initials: 'E', folder: '', favourite: false, passwordScore: 4, passwordIssues: [], securityLevel: 'good', issueKinds: [], tags: [], updatedAt: 1, ...overrides }
}

function draft(overrides: Partial<LoginInput> = {}): LoginInput {
  return { id: undefined, title: '', url: '', urls: [], tags: [], username: '', email: '', password: '', folder: '', totp: undefined, keepBackupCodes: false, backupCodes: [], recoveryEmail: '', recoveryPhone: '', recoveryNotApplicable: false, notes: '', ...overrides } as LoginInput
}

function open(entries: VaultEntrySummary[], loginDraft: LoginInput = draft(), folderOptions = [{ id: 'work', name: 'Work' }]) {
  const stores = createAppStores()
  stores.vault.patch({ snapshot: { entries } as unknown as VaultSnapshot })
  render(LoginEditor, {
    props: { loginDraft, folderOptions, onSubmit: vi.fn(), onClose: vi.fn(), onDelete: vi.fn() },
    context: new Map([[APP_STORES, stores]]),
  } as never)
}

const nameField = () => document.querySelector<HTMLInputElement>('input[name="login-title"]')!
const urlField = () => document.querySelector<HTMLInputElement>('input[name="login-url"]')!
const tagsField = () => document.querySelector<HTMLInputElement>('input[name="login-tags"]')!

async function typeInto(input: HTMLInputElement, value: string) {
  input.value = value
  await fireEvent.input(input)
}

test('typing a website names a new login after it, and keeps following the website while the name is untouched', async () => {
  open([])
  await typeInto(urlField(), 'github.com')
  expect(nameField().value).toBe('Github')
  await typeInto(urlField(), 'https://www.gitlab.com/login')
  expect(nameField().value).toBe('Gitlab')
})

test('a name the person typed is never replaced by the website', async () => {
  open([])
  await typeInto(nameField(), 'Work git')
  await typeInto(urlField(), 'github.com')
  expect(nameField().value).toBe('Work git')
})

test('a name that was suggested and then edited is left alone', async () => {
  open([])
  await typeInto(urlField(), 'github.com')
  await typeInto(nameField(), 'GitHub')
  await typeInto(urlField(), 'gitlab.com')
  expect(nameField().value).toBe('GitHub')
})

test('clearing the name lets the website suggest it again', async () => {
  open([])
  await typeInto(nameField(), 'Mine')
  await typeInto(nameField(), '')
  await typeInto(urlField(), 'github.com')
  expect(nameField().value).toBe('Github')
})

test('an existing login keeps its name when its website is edited', async () => {
  open([], draft({ id: 'login-a', title: 'Northwind', url: 'northwind.example.test' }))
  await typeInto(urlField(), 'contoso.example.test')
  expect(nameField().value).toBe('Northwind')
})

test('it says which logins already exist for the website, so a duplicate is noticed', async () => {
  open([summary('Northwind', { updatedAt: 5 }), summary('Northwind work', { site: 'login.example.test', updatedAt: 9 }), summary('Other', { site: 'other.test' })])
  await typeInto(urlField(), 'https://example.test')
  expect(screen.getByRole('status').textContent).toBe('You already have Northwind work and Northwind on this site.')
})

test('with many existing logins it names the newest and counts the rest', async () => {
  open([summary('One', { updatedAt: 3 }), summary('Two', { updatedAt: 2 }), summary('Three', { updatedAt: 1 })])
  await typeInto(urlField(), 'example.test')
  expect(screen.getByRole('status').textContent).toBe('You already have One and 2 more on this site.')
})

test('it does not count the login being edited, and says nothing for a new site', async () => {
  open([summary('login-a', { title: 'Northwind' })], draft({ id: 'login-a', title: 'Northwind', url: 'example.test' }))
  expect(screen.queryByRole('status')).toBeNull()
  await typeInto(urlField(), 'brand-new.test')
  expect(screen.queryByRole('status')).toBeNull()
})

test('it offers the folder the other logins for this site are in, and one click uses it', async () => {
  open([summary('Northwind', { folderId: 'work', folder: 'Work' })])
  await typeInto(urlField(), 'example.test')
  await fireEvent.click(screen.getByRole('button', { name: 'Put it in Work' }))
  expect(screen.queryByRole('button', { name: 'Put it in Work' })).toBeNull()
  expect(document.body.textContent).toContain('Work')
})

test('it offers tags used before and adds the one that is clicked, once', async () => {
  open([summary('Northwind', { tags: ['mail', 'work'] })])
  await typeInto(urlField(), 'example.test')
  await fireEvent.click(screen.getByRole('button', { name: 'Add tag mail' }))
  expect(tagsField().value).toBe('mail')
  expect(screen.queryByRole('button', { name: 'Add tag mail' })).toBeNull()
  await fireEvent.click(screen.getByRole('button', { name: 'Add tag work' }))
  expect(tagsField().value).toBe('mail, work')
})

test('the user name and email lists are asked for again when the website changes, ranked for that site', async () => {
  open([])
  const username = document.querySelector<HTMLInputElement>('input[name="login-username"]')!
  await typeInto(urlField(), 'example.test')
  await fireEvent.focus(username)
  expect(vaultApi.suggestFieldValues).toHaveBeenLastCalledWith('username', 'example.test')
  await fireEvent.focus(username)
  expect(vaultApi.suggestFieldValues).toHaveBeenCalledTimes(1)
  await typeInto(urlField(), 'other.test')
  await fireEvent.focus(username)
  expect(vaultApi.suggestFieldValues).toHaveBeenLastCalledWith('username', 'other.test')
})

test('a new login that opens with a website already filled in is named after it', async () => {
  open([], draft({ url: 'https://www.github.com/login' }))
  await Promise.resolve()
  expect(nameField().value).toBe('Github')
  await typeInto(urlField(), 'gitlab.com')
  expect(nameField().value).toBe('Gitlab')
})

test('a new login that opens with its own name keeps it', async () => {
  open([], draft({ title: 'Mine', url: 'github.com' }))
  await Promise.resolve()
  expect(nameField().value).toBe('Mine')
})

test('choosing the suggested folder counts as an edit, so closing asks before discarding it', async () => {
  open([summary('Northwind', { folderId: 'work', folder: 'Work' })], draft({ url: 'https://example.test' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Put it in Work' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(document.body.textContent).toContain('Discard your changes?')
})

test('a slow answer for an earlier website never replaces the list for the current one', async () => {
  const answers: Array<(values: string[]) => void> = []
  vaultApi.suggestFieldValues.mockImplementation(() => new Promise<string[]>((resolve) => answers.push(resolve)))
  open([])
  const username = document.querySelector<HTMLInputElement>('input[name="login-username"]')!
  await typeInto(urlField(), 'first.test')
  await fireEvent.focus(username)
  await typeInto(urlField(), 'second.test')
  await fireEvent.focus(username)
  answers[1](['second@example.test'])
  await new Promise((resolve) => setTimeout(resolve))
  answers[0](['first@example.test'])
  await new Promise((resolve) => setTimeout(resolve))
  const values = [...document.querySelectorAll<HTMLOptionElement>('#username-suggestions option')].map((option) => option.value)
  expect(values).toEqual(['second@example.test'])
})

test('a failed answer for an earlier website does not stop the current website from being asked for', async () => {
  const answers: Array<{ resolve: (values: string[]) => void; reject: (error: Error) => void }> = []
  vaultApi.suggestFieldValues.mockImplementation(() => new Promise<string[]>((resolve, reject) => answers.push({ resolve, reject })))
  open([])
  const username = document.querySelector<HTMLInputElement>('input[name="login-username"]')!
  await typeInto(urlField(), 'first.test')
  await fireEvent.focus(username)
  await typeInto(urlField(), 'second.test')
  await fireEvent.focus(username)
  answers[1].resolve(['second@example.test'])
  await new Promise((resolve) => setTimeout(resolve))
  answers[0].reject(new Error('Fictional failure'))
  await new Promise((resolve) => setTimeout(resolve))
  await fireEvent.focus(username)
  expect(vaultApi.suggestFieldValues).toHaveBeenCalledTimes(2)
})

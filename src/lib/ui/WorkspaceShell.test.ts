/* @vitest-environment jsdom */
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { LoginCard } from '../types'
import WorkspaceShell from './WorkspaceShell.svelte'

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

function loginCard(overrides: Partial<LoginCard> = {}): LoginCard {
  return { id: 'login-a', title: 'Northwind', site: '', initials: 'N', hasPassword: true, favourite: false, ...overrides } as LoginCard
}

function renderShell(overrides: Record<string, unknown> = {}, stores = createAppStores()) {
  stores.vault.patch({
    status: { exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 1 },
  })
  const props = {
    navigation: [],
    onNavigate: vi.fn(),
    onLock: vi.fn(),
    onDismissNotice: vi.fn(),
    onDismissError: vi.fn(),
    onFocusResults: vi.fn(),
    onCopyTotp: vi.fn(),
    onOpenSelectedSite: vi.fn(),
    ...overrides,
  }
  const rendered = render(WorkspaceShell, {
    props,
    context: new Map([[APP_STORES, stores]]),
  } as never)
  return { rendered, stores, props }
}

test('Ctrl T copies the one-time code only when the selected login has one', async () => {
  const { props, stores } = renderShell()
  await fireEvent.keyDown(document.body, { key: 't', ctrlKey: true })
  expect(props.onCopyTotp).not.toHaveBeenCalled()

  stores.vault.patch({ loginCard: loginCard({ totpCode: '123456' }) })
  await fireEvent.keyDown(document.body, { key: 't', ctrlKey: true })
  expect(props.onCopyTotp).toHaveBeenCalledOnce()
})

test('Ctrl O opens the selected site only when the login has a url', async () => {
  const { props, stores } = renderShell()
  await fireEvent.keyDown(document.body, { key: 'o', ctrlKey: true })
  expect(props.onOpenSelectedSite).not.toHaveBeenCalled()

  stores.vault.patch({ loginCard: loginCard({ url: 'https://northwind.example' }) })
  await fireEvent.keyDown(document.body, { key: 'o', ctrlKey: true })
  expect(props.onOpenSelectedSite).toHaveBeenCalledOnce()
})

test('Ctrl J jumps to the search results from inside the search field', async () => {
  const { props } = renderShell()
  const input = document.createElement('input')
  document.body.appendChild(input)

  await fireEvent.keyDown(input, { key: 'j', ctrlKey: true })

  expect(props.onFocusResults).toHaveBeenCalledOnce()
})

test('Ctrl J stays quiet while the vault is locked or another view is open', async () => {
  const stores = createAppStores()
  const { props } = renderShell({}, stores)
  stores.vault.patch({ status: { exists: true, unlocked: false, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 1 } })
  await fireEvent.keyDown(document.body, { key: 'j', ctrlKey: true })
  expect(props.onFocusResults).not.toHaveBeenCalled()

  stores.vault.patch({ status: { exists: true, unlocked: true, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 1 } })
  stores.selection.patch({ activeView: 'settings' })
  await fireEvent.keyDown(document.body, { key: 'j', ctrlKey: true })
  expect(props.onFocusResults).not.toHaveBeenCalled()
})

test('Ctrl C copies the password of the open login', async () => {
  const { props, stores } = renderShell({ onCopyPassword: vi.fn(), onCopyUsername: vi.fn() })
  stores.vault.patch({ loginCard: loginCard() })
  await fireEvent.keyDown(document.body, { key: 'c', ctrlKey: true })
  expect(props.onCopyPassword).toHaveBeenCalledOnce()
})

test('Ctrl C leaves text the person has selected to the ordinary copy instead of replacing the clipboard with the password', async () => {
  const { props, stores } = renderShell({ onCopyPassword: vi.fn(), onCopyUsername: vi.fn() })
  stores.vault.patch({ loginCard: loginCard() })
  const note = document.createElement('p')
  note.textContent = 'A line from the notes that I want to copy'
  document.body.appendChild(note)
  const range = document.createRange()
  range.selectNodeContents(note)
  window.getSelection()?.removeAllRanges()
  window.getSelection()?.addRange(range)
  const event = new KeyboardEvent('keydown', { key: 'c', ctrlKey: true, bubbles: true, cancelable: true })
  document.body.dispatchEvent(event)
  expect(props.onCopyPassword).not.toHaveBeenCalled()
  expect(event.defaultPrevented).toBe(false)
  window.getSelection()?.removeAllRanges()
})

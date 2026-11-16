/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { BrowserFillRequest, BrowserSaveRequest } from '../types'
import BrowserFillApprovalModal from './BrowserFillApprovalModal.svelte'
import BrowserSaveApprovalModal from './BrowserSaveApprovalModal.svelte'

vi.mock('../vault', () => ({ previewMode: false, getBrowserApprovalWait: vi.fn().mockResolvedValue(0) }))

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

const candidate = {
  id: 'login-a',
  title: 'Northwind',
  username: 'fictional-user',
  email: '',
  savedOrigin: 'https://northwind.example.test',
  matchKind: 'site' as const,
}

test('a site match names the saved address and the page address', () => {
  const request: BrowserFillRequest = {
    approvalId: 'approval-a',
    origin: 'https://login.northwind.example.test',
    hostname: 'login.northwind.example.test',
    candidates: [candidate],
    expiresInSeconds: 30,
    expiresAtUnixMs: Date.now() + 30_000,
  }
  const stores = createAppStores()
  stores.browserFill.patch({ request, selectedId: 'login-a' })
  render(BrowserFillApprovalModal, {
    props: { request, onCancel: vi.fn(), onConfirm: vi.fn() },
    context: new Map([[APP_STORES, stores]]),
  } as never)

  const note = screen.getByText('Matched by site').closest('p')!
  expect(note.textContent).toContain('https://northwind.example.test')
  expect(note.textContent).toContain('https://login.northwind.example.test')
  expect(screen.getByText('Site match')).toBeTruthy()
})

test('the save prompt offers never for this site next to discard', async () => {
  const request: BrowserSaveRequest = {
    approvalId: 'approval-b',
    origin: 'https://signup.northwind.example.test',
    hostname: 'signup.northwind.example.test',
    kind: 'new',
    title: 'Northwind',
    username: 'fictional-user',
    candidates: [],
    expiresInSeconds: 30,
    expiresAtUnixMs: Date.now() + 30_000,
  }
  const onNeverForSite = vi.fn()
  const stores = createAppStores()
  stores.browserSave.patch({ request })
  render(BrowserSaveApprovalModal, {
    props: { request, onCancel: vi.fn(), onConfirm: vi.fn(), onNeverForSite },
    context: new Map([[APP_STORES, stores]]),
  } as never)

  const button = screen.getByRole('button', { name: 'Never for this site' }) as HTMLButtonElement
  await vi.waitFor(() => expect(button.disabled).toBe(false))
  button.click()
  expect(onNeverForSite).toHaveBeenCalledTimes(1)
  expect(screen.getByRole('button', { name: 'Save login' })).toBeTruthy()
})

/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { BrowserFillRequest } from '../types'
import BrowserFillApprovalModal from './BrowserFillApprovalModal.svelte'

const vaultApi = vi.hoisted(() => ({
  getBrowserApprovalWait: vi.fn(),
}))

vi.mock('../vault', () => ({ previewMode: false, ...vaultApi }))

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

function fillRequest(): BrowserFillRequest {
  return {
    approvalId: 'approval-a',
    origin: 'https://northwind.example.test',
    hostname: 'northwind.example.test',
    candidates: [{
      id: 'login-a',
      title: 'Northwind',
      username: 'fictional-user',
      email: '',
      savedOrigin: 'https://northwind.example.test',
      matchKind: 'exact',
    }] as BrowserFillRequest['candidates'],
    expiresInSeconds: 30,
    expiresAtUnixMs: Date.now() + 30_000,
  }
}

function renderModal() {
  const stores = createAppStores()
  stores.browserFill.patch({ request: fillRequest(), selectedId: 'login-a' })
  return render(BrowserFillApprovalModal, {
    props: { request: fillRequest(), onCancel: vi.fn(), onConfirm: vi.fn() },
    context: new Map([[APP_STORES, stores]]),
  } as never)
}

test('the approve button stays disabled and says why while the backend reports a wait', async () => {
  vaultApi.getBrowserApprovalWait.mockResolvedValue(600)
  renderModal()
  await vi.waitFor(() => expect(screen.getByText('Ready in a moment')).toBeTruthy())

  expect((screen.getByRole('button', { name: 'Fill login' }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: 'Not now' }) as HTMLButtonElement).disabled).toBe(false)
})

test('the approve button opens once the backend reports no wait', async () => {
  vaultApi.getBrowserApprovalWait.mockResolvedValue(0)
  renderModal()

  await vi.waitFor(() => expect((screen.getByRole('button', { name: 'Fill login' }) as HTMLButtonElement).disabled).toBe(false))
  expect(screen.getByText(/Expires in/)).toBeTruthy()
})

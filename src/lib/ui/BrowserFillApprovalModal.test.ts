/* @vitest-environment jsdom */
import { cleanup, render } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { BrowserFillRequest } from '../types'
import BrowserFillApprovalModal from './BrowserFillApprovalModal.svelte'

vi.mock('../approval-wait', async () => {
  const { readable } = await import('svelte/store')
  return { approvalWait: readable({ ms: 0, windowFocused: true }), approvalFooterText: () => 'Expires in 30s' }
})
vi.mock('../release-record-api', () => ({ getReleaseRecordHint: vi.fn(async () => null) }))

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

test('a stored title, username or site with a direction override is shown with visible stand-ins', () => {
  const stores = createAppStores()
  const request: BrowserFillRequest = {
    approvalId: 'fill-a',
    origin: 'https://northwind.example',
    hostname: 'northwind.example',
    candidates: [{ id: 'login-a', title: 'Mallory \u202Egnp.exe\u202C Item', username: 'casey\u2067@evil', email: '', savedOrigin: 'https://north\u202Eelpmaxe.wind', matchKind: 'exact' }],
    expiresInSeconds: 30,
    expiresAtUnixMs: Date.now() + 30_000,
  }
  stores.browserFill.patch({ request, selectedId: 'login-a' })
  render(BrowserFillApprovalModal, { props: { request, onCancel: vi.fn(), onConfirm: vi.fn() }, context: new Map([[APP_STORES, stores]]) } as never)
  const label = document.querySelector('.browser-fill-candidates label') as HTMLElement
  expect(label.textContent).not.toMatch(/[\u202A-\u202E\u2066-\u2069]/)
  expect([...label.querySelectorAll('bdi')].map((part) => part.textContent)).toEqual(['Mallory ?gnp.exe? Item', 'casey?@evil', 'https://north?elpmaxe.wind'])
})

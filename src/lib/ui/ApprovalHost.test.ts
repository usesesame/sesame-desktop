/* @vitest-environment jsdom */
import { cleanup, fireEvent, render } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import ApprovalHost from './ApprovalHost.svelte'

vi.mock('../approval-wait', async () => {
  const { readable } = await import('svelte/store')
  const ready = readable({ ms: 0, windowFocused: true })
  return { approvalWait: ready, createApprovalWait: () => ready, approvalFooterText: () => 'Expires in 30s' }
})
vi.mock('../release-record-api', () => ({ getReleaseRecordHint: vi.fn(async () => null) }))
vi.mock('../terminal-api', () => ({ getTerminalApprovalWait: vi.fn(async () => 0) }))

type Stores = ReturnType<typeof createAppStores>
type Kind = 'browserFill' | 'browserIdentityFill' | 'browserCardFill' | 'browserTotpFill' | 'browserSave' | 'browserChange' | 'browserCreate' | 'terminalApproval'

const page = { origin: 'https://shop.example.test', hostname: 'shop.example.test', expiresInSeconds: 30 }

function candidate(id: string) {
  return { id, title: `Fictional ${id}`, username: 'casey@example.test', email: '', savedOrigin: 'https://shop.example.test', matchKind: 'exact' as const, label: `Fictional ${id}`, fullName: 'Casey Example', brand: 'Visa', last4: '0002', cardholderName: 'Casey Example', kind: 'login', fieldHidden: false, fieldName: 'password' }
}

function request(kind: Kind, approvalId: string, ids = ['candidate-a']) {
  const candidates = ids.map(candidate)
  const expiresAtUnixMs = Date.now() + 30_000
  if (kind === 'terminalApproval') {
    return { approvalId, command: 'get', field: 'password', fieldHidden: false, copy: false, candidates, terminal: 'pts/3', program: { reportedName: 'bash' }, remote: false, canAllowTerminal: false, needsPresence: false, missingField: false, allowed: false, expiresInMs: 30_000 }
  }
  if (kind === 'browserCreate') return { ...page, approvalId, expiresAtUnixMs }
  if (kind === 'browserSave') return { ...page, approvalId, kind: 'new', title: 'shop.example.test', username: 'casey@example.test', candidates: [], expiresAtUnixMs }
  if (kind === 'browserChange') return { ...page, approvalId, candidates, unconfirmed: [], expiresAtUnixMs }
  return { ...page, approvalId, requestedFields: [], candidates, expiresAtUnixMs }
}

const kinds: Kind[] = ['browserFill', 'browserIdentityFill', 'browserCardFill', 'browserTotpFill', 'browserSave', 'browserChange', 'browserCreate', 'terminalApproval']

let stores: Stores
let calls: Record<string, unknown[]>

function show(kind: Kind, approvalId: string, ids?: string[]) {
  const shown = request(kind, approvalId, ids) as { candidates?: Array<{ id: string }> }
  const selectedId = kind === 'browserSave' || kind === 'browserCreate' ? '' : shown.candidates?.[0]?.id ?? ''
  const extra = kind === 'terminalApproval' ? { expiresAt: Date.now() + 30_000 } : {}
  stores[kind].patch({ request: shown, selectedId, ...extra } as never)
}

function mount() {
  const resolver = (name: string) => ({ resolve: vi.fn(async (choice: unknown) => { calls[name].push(choice) }) })
  const allow = vi.fn(async () => { calls.terminalApproval.push(stores.terminalApproval.value().request?.approvalId) })
  const props = {
    fill: resolver('browserFill'),
    identity: resolver('browserIdentityFill'),
    card: resolver('browserCardFill'),
    totp: resolver('browserTotpFill'),
    save: { ...resolver('browserSave'), neverForSite: vi.fn(async () => {}) },
    change: resolver('browserChange'),
    create: resolver('browserCreate'),
    terminal: { allow, deny: vi.fn(), dismiss: vi.fn(), expire: vi.fn(), select: vi.fn(), setAllowTerminal: vi.fn(), setSecret: vi.fn() },
  }
  render(ApprovalHost, { props, context: new Map([[APP_STORES, stores]]) } as never)
}

function primary() {
  return document.querySelector('[data-modal-shell] .primary-button') as HTMLButtonElement
}

beforeEach(() => {
  vi.useFakeTimers()
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
  stores = createAppStores()
  calls = Object.fromEntries(kinds.map((kind) => [kind, []]))
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
  vi.useRealTimers()
})

describe.each(kinds)('a %s approval that replaces another one', (kind) => {
  test('is not clickable until it has stayed on screen for its own delay', async () => {
    show(kind, 'approval-a')
    mount()
    await vi.advanceTimersByTimeAsync(800)
    expect(primary().disabled).toBe(false)

    const first = document.querySelector('[role="dialog"]')
    show(kind, 'approval-b')
    await vi.advanceTimersByTimeAsync(0)
    expect(document.querySelector('[role="dialog"]')).not.toBe(first)
    await fireEvent.click(primary())
    expect(calls[kind]).toEqual([])
    expect(primary().disabled).toBe(true)

    await vi.advanceTimersByTimeAsync(800)
    await fireEvent.click(primary())
    expect(calls[kind]).toHaveLength(1)
    if (kind === 'terminalApproval') expect(calls[kind]).toEqual(['approval-b'])
  })
})

test('an armed approval whose offered items or chosen item change waits its delay again', async () => {
  show('browserFill', 'approval-a', ['candidate-a', 'candidate-b'])
  mount()
  await vi.advanceTimersByTimeAsync(800)
  expect(primary().disabled).toBe(false)

  stores.browserFill.patch({ selectedId: 'candidate-b' })
  await vi.advanceTimersByTimeAsync(0)
  await fireEvent.click(primary())
  expect(calls.browserFill).toEqual([])

  await vi.advanceTimersByTimeAsync(800)
  stores.browserFill.patch({ request: { ...stores.browserFill.value().request!, candidates: [candidate('candidate-b'), candidate('candidate-c')] } })
  await vi.advanceTimersByTimeAsync(0)
  await fireEvent.click(primary())
  expect(calls.browserFill).toEqual([])

  await vi.advanceTimersByTimeAsync(800)
  await fireEvent.click(primary())
  expect(calls.browserFill).toEqual(['candidate-b'])
})

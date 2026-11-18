import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { CliApprovalCancelledEvent } from './generated/CliApprovalCancelledEvent'
import type { CliApprovalRequestEvent } from './generated/CliApprovalRequestEvent'
import type { CliDecisionInput } from './generated/CliDecisionInput'
import type { CliUnlockEndedEvent } from './generated/CliUnlockEndedEvent'
import type { CliUnlockRequestEvent } from './generated/CliUnlockRequestEvent'
import type { TerminalAllowanceList } from './generated/TerminalAllowanceList'
import type { TerminalToolStatus } from './generated/TerminalToolStatus'

export type { CliApprovalCancelledEvent, CliApprovalRequestEvent, CliDecisionInput, CliUnlockEndedEvent, CliUnlockRequestEvent, TerminalAllowanceList, TerminalToolStatus }

const previewMode = typeof window === 'undefined' || !(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await tauriInvoke<T>(cmd, args)
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error))
  }
}

function previewQuery(name: string): string | null {
  return typeof window === 'undefined' ? null : new URLSearchParams(window.location.search).get(name)
}

export const PREVIEW_TERMINAL_APPROVAL_ID = 'preview-terminal-approval'

const previewBase: CliApprovalRequestEvent = {
  approvalId: PREVIEW_TERMINAL_APPROVAL_ID,
  command: 'get',
  field: 'password',
  fieldHidden: true,
  copy: false,
  candidates: [{ id: 'gmail', kind: 'login', title: 'Gmail', fieldName: 'Password', fieldHidden: true }],
  terminal: 'pts/3',
  program: { reportedName: 'bash' },
  remote: false,
  canAllowTerminal: true,
  needsPresence: false,
  allowed: false,
  expiresInMs: 600_000,
}

const previewRequests: Record<string, Partial<CliApprovalRequestEvent>> = {
  get: {},
  list: { command: 'list', field: undefined, fieldHidden: false, candidates: [] },
  totp: { command: 'totp', field: undefined, fieldHidden: false, copy: true, candidates: [{ id: 'gmail', kind: 'login', title: 'Gmail', fieldHidden: false }] },
  presence: { needsPresence: true },
  chooser: {
    field: 'field:0',
    fieldHidden: true,
    candidates: [
      { id: 'gmail', kind: 'login', title: 'Gmail', fieldName: 'Recovery PIN', fieldHidden: true },
      { id: 'github', kind: 'login', title: 'Gmail', fieldName: 'Member number', fieldHidden: false },
    ],
  },
  allowed: { allowed: true, canAllowTerminal: false, needsPresence: true },
  remote: { remote: true, program: { reportedName: 'sshd' }, terminal: 'pts/7', canAllowTerminal: true },
  'no-terminal': { terminal: undefined, program: { reportedName: 'cron' }, canAllowTerminal: false },
  'not-found': { candidates: [], notFound: 'Northwnd mail', canAllowTerminal: false, fieldHidden: false },
  hostile: {
    field: `api\u202Etoken\u0007${'x'.repeat(200)}`,
    fieldHidden: true,
    candidates: [{ id: 'gmail', kind: 'login', title: `Gm${'\u0301'.repeat(45)}ail\u3164\u2800\u202E evil.example \u200Bterminal: pts/1 ${'W'.repeat(300)}`, fieldName: `Allow\u202E pts/1 ${'z'.repeat(120)}`, fieldHidden: true }],
    program: { reportedName: `sesame\u202E\u0000 Allow${'\u0336'.repeat(30)} \u115F\u1160 ${'A'.repeat(120)}` },
    terminal: 'pts/3',
  },
}

export function previewTerminalRequest(): CliApprovalRequestEvent | null {
  if (!previewMode) return null
  const wanted = previewQuery('previewTerminal')
  if (!wanted || !Object.prototype.hasOwnProperty.call(previewRequests, wanted)) return null
  return { ...previewBase, ...previewRequests[wanted] }
}

export function previewTerminalUnlock(): CliUnlockRequestEvent | null {
  if (!previewMode || previewQuery('previewTerminal') !== 'unlock') return null
  return { command: 'get', field: 'password', copy: false, terminal: 'pts/3', program: { reportedName: 'bash' }, remote: false }
}

function previewAllowances(): TerminalAllowanceList {
  if (previewQuery('previewTerminalSettings') === 'empty') return { allowances: [], requests: [] }
  const now = Math.floor(Date.now() / 1_000)
  return {
    allowances: [
      { terminal: 'pts/3', program: { reportedName: 'bash' }, remote: false, expiresInMs: 212_000 },
      { terminal: 'pts/7', program: { reportedName: 'zsh' }, remote: true, expiresInMs: 41_000 },
    ],
    requests: [
      { at: now - 30, terminal: 'pts/3', command: 'get', itemId: 'github', itemKind: 'login', field: 'username' },
      { at: now - 95, terminal: 'pts/3', command: 'totp', itemId: 'gmail', itemKind: 'login', field: 'totp' },
      { at: now - 140, terminal: 'pts/7', command: 'list' },
    ],
  }
}

function previewStatus(): TerminalToolStatus {
  const wanted = previewQuery('previewTerminalStatus')
  if (wanted === 'servedElsewhere') return { supported: true, available: false, servedElsewhere: true, code: 'servedElsewhere' }
  if (wanted === 'failed') return { supported: true, available: false, servedElsewhere: false, code: 'failed' }
  if (wanted === 'unsupported') return { supported: false, available: false, servedElsewhere: false, code: 'unsupported' }
  return { supported: true, available: true, servedElsewhere: false, code: 'ready' }
}

export async function getPendingTerminalRequest(): Promise<CliApprovalRequestEvent | null> {
  if (previewMode) return null
  return invoke<CliApprovalRequestEvent | null>('get_pending_terminal_request')
}

export async function getTerminalApprovalWait(): Promise<number> {
  if (previewMode) return 0
  return invoke<number>('get_terminal_approval_wait')
}

export async function resolveTerminalRequest(decision: CliDecisionInput): Promise<void> {
  if (previewMode) return
  await invoke<void>('resolve_terminal_request', { decision })
}

export async function listTerminalPermissions(): Promise<TerminalAllowanceList> {
  if (previewMode) return previewAllowances()
  return invoke<TerminalAllowanceList>('list_terminal_permissions')
}

export async function forgetTerminalPermissions(): Promise<void> {
  if (previewMode) return
  await invoke<void>('forget_terminal_permissions')
}

export async function getTerminalStatus(): Promise<TerminalToolStatus> {
  if (previewMode) return previewStatus()
  return invoke<TerminalToolStatus>('get_terminal_status')
}

function stopQuietly(stop: UnlistenFn): Promise<unknown> {
  try {
    return Promise.resolve(stop()).catch(() => undefined)
  } catch {
    return Promise.resolve()
  }
}

async function listenToBoth(first: Promise<UnlistenFn>, second: Promise<UnlistenFn>): Promise<UnlistenFn> {
  const results = await Promise.allSettled([first, second])
  const stops = results.flatMap((result) => (result.status === 'fulfilled' ? [result.value] : []))
  const failure = results.find((result) => result.status === 'rejected')
  if (failure) {
    await Promise.all(stops.map(stopQuietly))
    throw failure.reason
  }
  return () => {
    for (const stop of stops) void stopQuietly(stop)
  }
}

export async function subscribeTerminalApproval(handlers: {
  request: (payload: CliApprovalRequestEvent) => void
  cancelled: (payload: CliApprovalCancelledEvent) => void
}): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listenToBoth(
    listen<CliApprovalRequestEvent>('terminal-approval-request', ({ payload }) => handlers.request(payload)),
    listen<CliApprovalCancelledEvent>('terminal-approval-cancelled', ({ payload }) => handlers.cancelled(payload)),
  )
}

export async function subscribeTerminalUnlock(handlers: {
  request: (payload: CliUnlockRequestEvent) => void
  ended: (payload: CliUnlockEndedEvent) => void
}): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listenToBoth(
    listen<CliUnlockRequestEvent>('terminal-unlock-request', ({ payload }) => handlers.request(payload)),
    listen<CliUnlockEndedEvent>('terminal-unlock-ended', ({ payload }) => handlers.ended(payload)),
  )
}

export async function onTerminalPermissionsChanged(handler: () => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen('terminal-permissions-changed', () => handler())
}

export async function onTerminalStatusChanged(handler: (status: TerminalToolStatus) => void): Promise<UnlistenFn> {
  if (previewMode) return () => {}
  return listen<TerminalToolStatus>('terminal-status-changed', ({ payload }) => handler(payload))
}

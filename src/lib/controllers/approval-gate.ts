import { derived, get, writable, type Readable } from 'svelte/store'
import type { AppStores } from '../stores/app-stores'

export const APPROVAL_KINDS = [
  'browserFill',
  'browserIdentityFill',
  'browserCardFill',
  'browserTotpFill',
  'browserSave',
  'browserChange',
  'browserCreate',
  'terminalApproval',
] as const

export type ApprovalKind = (typeof APPROVAL_KINDS)[number]

export const APPROVAL_SETTLE_MS = 750

export function settleKeyFor(request: { approvalId: string; candidates?: ReadonlyArray<{ id: string }> }, selectedId = '', ...shown: unknown[]): string {
  return JSON.stringify([request.approvalId, (request.candidates ?? []).map((candidate) => candidate.id), selectedId, ...shown])
}

const surfaces = writable({ approvals: 0, prompts: 0 })

function claim(field: 'approvals' | 'prompts'): () => void {
  surfaces.update((count) => ({ ...count, [field]: count[field] + 1 }))
  let released = false
  return () => {
    if (released) return
    released = true
    surfaces.update((count) => ({ ...count, [field]: Math.max(0, count[field] - 1) }))
  }
}

export function claimApprovalSurface(): () => void {
  return claim('approvals')
}

export function claimPromptSurface(): () => void {
  return claim('prompts')
}

export const approvalOnScreen: Readable<boolean> = derived(surfaces, (count) => count.approvals > 0)
export const promptOnScreen: Readable<boolean> = derived(surfaces, (count) => count.prompts > 0)

export function holdsApprovals(_node: HTMLElement) {
  return { destroy: claimPromptSurface() }
}

export interface ApprovalGate {
  held(kind: ApprovalKind): boolean
  whenClear(run: () => void): () => void
}

export function createApprovalGate(stores: AppStores, answering: Readable<boolean>): ApprovalGate {
  const blocked = derived([answering, promptOnScreen], ([open, onScreen]) => open || onScreen)
  const requests = derived(APPROVAL_KINDS.map((kind) => stores[kind]), (states) => states.some((state) => state.request !== null))

  function anotherRequest(kind: ApprovalKind): boolean {
    return APPROVAL_KINDS.some((other) => other !== kind && stores[other].value().request !== null)
  }

  function held(kind: ApprovalKind): boolean {
    return get(blocked) || anotherRequest(kind)
  }

  function whenClear(run: () => void): () => void {
    let wasClear = false
    return derived([blocked, requests], ([isBlocked, anyRequest]) => !isBlocked && !anyRequest).subscribe((clear) => {
      if (clear && !wasClear) run()
      wasClear = clear
    })
  }

  return { held, whenClear }
}

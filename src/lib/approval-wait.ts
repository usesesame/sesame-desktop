import { readable } from 'svelte/store'
import { getBrowserApprovalWait } from './vault'

export interface ApprovalWait {
  ms: number
  windowFocused: boolean
}

const WAIT_POLL_MS = 100
const READY_POLL_MS = 300
const unknownWait: ApprovalWait = { ms: 1, windowFocused: true }

export const approvalWait = readable<ApprovalWait>(unknownWait, (set) => {
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined

  async function refresh() {
    if (timer) clearTimeout(timer)
    let ms = unknownWait.ms
    try {
      ms = await getBrowserApprovalWait()
    } catch {
      ms = unknownWait.ms
    }
    if (stopped) return
    set({ ms, windowFocused: document.hasFocus() })
    timer = setTimeout(() => void refresh(), ms > 0 ? WAIT_POLL_MS : READY_POLL_MS)
  }

  const onFocusChange = () => void refresh()
  window.addEventListener('focus', onFocusChange)
  window.addEventListener('blur', onFocusChange)
  void refresh()

  return () => {
    stopped = true
    if (timer) clearTimeout(timer)
    window.removeEventListener('focus', onFocusChange)
    window.removeEventListener('blur', onFocusChange)
  }
})

export function approvalFooterText(remainingSeconds: number, wait: ApprovalWait): string {
  if (remainingSeconds === 0) return 'Request expired'
  if (wait.ms === 0) return `Expires in ${remainingSeconds}s`
  return wait.windowFocused ? 'Ready in a moment' : 'Click this window to approve'
}

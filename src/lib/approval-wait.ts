import { readable, type Readable } from 'svelte/store'
import { getBrowserApprovalWait } from './vault'

export interface ApprovalWait {
  ms: number
  windowFocused: boolean
}

const WAIT_POLL_MS = 100
const READY_POLL_MS = 300
const unknownWait: ApprovalWait = { ms: 1, windowFocused: true }

export function createApprovalWait(fetchWait: () => Promise<number>): Readable<ApprovalWait> {
  return readable<ApprovalWait>(unknownWait, (set) => {
    let stopped = false
    let timer: ReturnType<typeof setTimeout> | undefined
    let reading = false
    let readAgain = false

    async function refresh() {
      if (timer) clearTimeout(timer)
      timer = undefined
      if (reading) {
        readAgain = true
        return
      }
      reading = true
      let ms = unknownWait.ms
      try {
        ms = await fetchWait()
      } catch {
        ms = unknownWait.ms
      }
      reading = false
      if (stopped) return
      if (readAgain) {
        readAgain = false
        void refresh()
        return
      }
      set({ ms, windowFocused: document.hasFocus() })
      timer = setTimeout(() => void refresh(), ms > 0 ? WAIT_POLL_MS : READY_POLL_MS)
    }

    const onFocusChange = () => {
      set({ ...unknownWait, windowFocused: document.hasFocus() })
      void refresh()
    }
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
}

export const approvalWait = createApprovalWait(getBrowserApprovalWait)

export function approvalFooterText(remainingSeconds: number, wait: ApprovalWait): string {
  if (remainingSeconds === 0) return 'Request expired'
  if (wait.ms === 0) return `Expires in ${remainingSeconds}s`
  return wait.windowFocused ? 'Ready in a moment' : 'Click this window to approve'
}

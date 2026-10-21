import { get } from 'svelte/store'

import { platformCapabilities } from './platform'
import { recordActivity } from './vault'

export const ACTIVITY_REPORT_INTERVAL_MS = 5000

const inputEvents = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'] as const

export function startActivityReports(report: () => Promise<void> = recordActivity, now: () => number = Date.now): () => void {
  let lastReport = Number.NEGATIVE_INFINITY
  const onInput = () => {
    const capabilities = get(platformCapabilities)
    if (!capabilities.sessionAutoLock || capabilities.systemIdle) return
    const current = now()
    if (current - lastReport < ACTIVITY_REPORT_INTERVAL_MS) return
    lastReport = current
    void report().catch(() => undefined)
  }
  for (const name of inputEvents) window.addEventListener(name, onInput, { passive: true, capture: true })
  return () => {
    for (const name of inputEvents) window.removeEventListener(name, onInput, { capture: true })
  }
}

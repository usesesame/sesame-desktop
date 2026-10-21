/* @vitest-environment jsdom */
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ACTIVITY_REPORT_INTERVAL_MS, startActivityReports } from './activity'
import { platformCapabilities } from './platform'
import type { PlatformCapabilities } from './types'

const host: PlatformCapabilities = {
  os: 'linux',
  pinUnlock: false,
  biometricUnlock: false,
  autoType: false,
  browserIntegration: false,
  sessionAutoLock: true,
  systemIdle: false,
  screenLockMonitoring: true,
  quickAccessShortcut: false,
  accountLinking: false,
  desktopUpdates: false,
  windowControls: false,
}

describe('activity reports', () => {
  let stop: (() => void) | undefined

  afterEach(() => {
    stop?.()
    stop = undefined
    platformCapabilities.set({ ...host, sessionAutoLock: false })
  })

  it('reports input once per interval when the desktop reports no idle time', () => {
    platformCapabilities.set(host)
    let clock = 1_000
    const report = vi.fn().mockResolvedValue(undefined)
    stop = startActivityReports(report, () => clock)
    window.dispatchEvent(new Event('keydown'))
    window.dispatchEvent(new Event('pointermove'))
    expect(report).toHaveBeenCalledTimes(1)
    clock += ACTIVITY_REPORT_INTERVAL_MS - 1
    window.dispatchEvent(new Event('pointerdown'))
    expect(report).toHaveBeenCalledTimes(1)
    clock += 1
    window.dispatchEvent(new Event('wheel'))
    expect(report).toHaveBeenCalledTimes(2)
  })

  it('reports nothing when the desktop already reports idle time', () => {
    platformCapabilities.set({ ...host, systemIdle: true })
    const report = vi.fn().mockResolvedValue(undefined)
    stop = startActivityReports(report, () => 0)
    window.dispatchEvent(new Event('keydown'))
    expect(report).not.toHaveBeenCalled()
  })

  it('reports nothing where there is no automatic lock', () => {
    platformCapabilities.set({ ...host, sessionAutoLock: false })
    const report = vi.fn().mockResolvedValue(undefined)
    stop = startActivityReports(report, () => 0)
    window.dispatchEvent(new Event('keydown'))
    expect(report).not.toHaveBeenCalled()
  })

  it('keeps going when a report fails and stops listening when asked', async () => {
    platformCapabilities.set(host)
    let clock = 0
    const report = vi.fn().mockRejectedValue(new Error('fictional failure'))
    stop = startActivityReports(report, () => clock)
    window.dispatchEvent(new Event('keydown'))
    clock += ACTIVITY_REPORT_INTERVAL_MS
    window.dispatchEvent(new Event('keydown'))
    expect(report).toHaveBeenCalledTimes(2)
    stop()
    stop = undefined
    clock += ACTIVITY_REPORT_INTERVAL_MS
    window.dispatchEvent(new Event('keydown'))
    expect(report).toHaveBeenCalledTimes(2)
  })
})

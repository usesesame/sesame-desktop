// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest'

const eventApi = vi.hoisted(() => {
  ;(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {}
  return { listen: vi.fn() }
})

vi.mock('@tauri-apps/api/event', () => eventApi)
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))

const { subscribeTerminalApproval, subscribeTerminalUnlock } = await import('./terminal-api')

describe('terminal event listeners', () => {
  beforeEach(() => {
    eventApi.listen.mockReset()
  })

  it.each([
    ['approval', () => subscribeTerminalApproval({ request: () => {}, cancelled: () => {} })],
    ['unlock', () => subscribeTerminalUnlock({ request: () => {}, ended: () => {} })],
  ])('removes the %s listener that registered when the other one fails', async (_name, subscribe) => {
    const stopFirst = vi.fn()
    let finishFirst: (stop: () => void) => void = () => {}
    eventApi.listen
      .mockImplementationOnce(() => new Promise((resolve) => (finishFirst = resolve)))
      .mockImplementationOnce(() => Promise.reject(new Error('fictional listen failure')))
    const subscribed = subscribe()
    finishFirst(stopFirst)
    await expect(subscribed).rejects.toThrow('fictional listen failure')
    expect(stopFirst).toHaveBeenCalledTimes(1)
  })

  it('keeps both listeners when both register and removes both on cleanup', async () => {
    const stops = [vi.fn(), vi.fn()]
    eventApi.listen.mockResolvedValueOnce(stops[0]).mockResolvedValueOnce(stops[1])
    const stop = await subscribeTerminalApproval({ request: () => {}, cancelled: () => {} })
    expect(stops[0]).not.toHaveBeenCalled()
    stop()
    expect(stops[0]).toHaveBeenCalledTimes(1)
    expect(stops[1]).toHaveBeenCalledTimes(1)
  })
})

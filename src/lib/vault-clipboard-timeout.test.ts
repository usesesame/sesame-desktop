// @vitest-environment jsdom
import { expect, test, vi } from 'vitest'

const core = vi.hoisted(() => {
  ;(window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {}
  return { invoke: vi.fn() }
})

vi.mock('@tauri-apps/api/core', () => core)
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }))
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: vi.fn() }))

const { setClipboardClearSeconds } = await import('./vault')

test('terminal clipboard timeouts reach Sesame one at a time and in the order chosen', async () => {
  const finished: Array<() => void> = []
  core.invoke.mockImplementation(() => new Promise<void>((resolve) => finished.push(resolve)))
  const first = setClipboardClearSeconds(60)
  const second = setClipboardClearSeconds(10)
  await Promise.resolve()
  expect(core.invoke).toHaveBeenCalledTimes(1)
  expect(core.invoke).toHaveBeenLastCalledWith('set_terminal_clipboard_clear_seconds', { seconds: 60 })
  finished[0]()
  await first
  await vi.waitFor(() => expect(core.invoke).toHaveBeenCalledTimes(2))
  expect(core.invoke).toHaveBeenLastCalledWith('set_terminal_clipboard_clear_seconds', { seconds: 10 })
  finished[1]()
  await second
})

test('a failed update does not hold back the next one', async () => {
  core.invoke.mockReset()
  core.invoke.mockRejectedValueOnce(new Error('fictional failure')).mockResolvedValueOnce(undefined)
  await expect(setClipboardClearSeconds(30)).rejects.toThrow()
  await expect(setClipboardClearSeconds(10)).resolves.toBeUndefined()
  expect(core.invoke).toHaveBeenLastCalledWith('set_terminal_clipboard_clear_seconds', { seconds: 10 })
})

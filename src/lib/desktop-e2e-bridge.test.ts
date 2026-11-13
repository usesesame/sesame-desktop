/* @vitest-environment jsdom */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { answer } from './desktop-e2e-bridge'

const core = vi.hoisted(() => ({ invoke: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => core)

describe('desktop E2E bridge', () => {
  beforeEach(() => {
    core.invoke.mockReset()
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
  })

  it('answers the webview feature probe in the page without calling Rust', async () => {
    const result = await answer({ id: 7, command: 'desktop_e2e_webview_features', args: {} })

    expect(core.invoke).not.toHaveBeenCalled()
    expect(result).toEqual({
      id: 7,
      ok: true,
      value: { webgl: false, webgl2: false, audioContext: false, mediaDevices: false, mediaElements: true },
    })
  })

  it('reports a feature the page can still reach', async () => {
    vi.mocked(HTMLCanvasElement.prototype.getContext).mockImplementation(
      ((kind: string) => (kind === 'webgl' ? ({} as RenderingContext) : null)) as HTMLCanvasElement['getContext'],
    )

    const result = await answer({ id: 8, command: 'desktop_e2e_webview_features', args: {} })

    expect(result.value).toMatchObject({ webgl: true, webgl2: false })
  })

  it('passes every other command to the app and reports its failure', async () => {
    core.invoke.mockResolvedValueOnce({ unlocked: false })
    expect(await answer({ id: 9, command: 'get_vault_status', args: {} })).toEqual({ id: 9, ok: true, value: { unlocked: false } })
    expect(core.invoke).toHaveBeenCalledWith('get_vault_status', {})

    core.invoke.mockRejectedValueOnce('The vault is locked.')
    expect(await answer({ id: 10, command: 'lock_vault', args: {} })).toEqual({ id: 10, ok: false, error: 'The vault is locked.' })
  })

  it('does not treat an inherited property name as a page command', async () => {
    core.invoke.mockResolvedValueOnce(null)
    await answer({ id: 11, command: 'constructor', args: {} })
    expect(core.invoke).toHaveBeenCalledWith('constructor', {})
  })
})

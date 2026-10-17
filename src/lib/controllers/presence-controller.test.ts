import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { grantPresence } from '../vault'
import { createPresenceController } from './presence-controller'

vi.mock('../vault', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../vault')>()
  return { ...actual, grantPresence: vi.fn() }
})

beforeEach(() => {
  vi.mocked(grantPresence).mockReset()
})

describe('presence controller', () => {
  it('recognises only the host presence refusal', () => {
    const presence = createPresenceController()
    expect(presence.required(new Error('presenceRequired'))).toBe(true)
    expect(presence.required(new Error('Something else'))).toBe(false)
    expect(presence.required('presenceRequired')).toBe(false)
  })

  it('runs the waiting action once the master password is accepted and clears the field', async () => {
    const presence = createPresenceController()
    const run = vi.fn()
    vi.mocked(grantPresence).mockResolvedValue(undefined)
    presence.ask('copy-field', run)
    presence.state.patch({ secret: 'fictional master password' })

    await presence.confirm()

    expect(grantPresence).toHaveBeenCalledWith('fictional master password')
    expect(run).toHaveBeenCalledTimes(1)
    expect(get(presence.state)).toEqual({ open: false, intent: 'reveal-field', secret: '', error: '', working: false })
  })

  it('keeps the prompt open with the error and does not run the action after a wrong password', async () => {
    const presence = createPresenceController()
    const run = vi.fn()
    vi.mocked(grantPresence).mockRejectedValue(new Error('That master password does not open this vault.'))
    presence.ask('check-password', run)
    presence.state.patch({ secret: 'fictional wrong password' })

    await presence.confirm()

    expect(run).not.toHaveBeenCalled()
    expect(get(presence.state)).toMatchObject({ open: true, error: 'That master password does not open this vault.', secret: '', working: false })
  })

  it('does nothing without a typed password', async () => {
    const presence = createPresenceController()
    const run = vi.fn()
    presence.ask('reveal-field', run)

    await presence.confirm()

    expect(grantPresence).not.toHaveBeenCalled()
    expect(run).not.toHaveBeenCalled()
  })

  it('forgets the waiting action on cancel so a later confirm runs nothing', async () => {
    const presence = createPresenceController()
    const run = vi.fn()
    presence.ask('reveal-field', run)

    presence.cancel()
    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()

    expect(run).not.toHaveBeenCalled()
    expect(grantPresence).not.toHaveBeenCalled()
  })

  it('ignores a second confirm while the first is still checking the password', async () => {
    const presence = createPresenceController()
    const run = vi.fn()
    let release: () => void = () => {}
    vi.mocked(grantPresence).mockImplementation(() => new Promise<void>((resolve) => { release = resolve }))
    presence.ask('copy-field', run)
    presence.state.patch({ secret: 'fictional master password' })

    const first = presence.confirm()
    presence.state.patch({ secret: 'fictional master password' })
    await presence.confirm()
    release()
    await first

    expect(grantPresence).toHaveBeenCalledTimes(1)
    expect(run).toHaveBeenCalledTimes(1)
  })
})

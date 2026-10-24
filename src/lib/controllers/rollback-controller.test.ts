import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createRollbackController } from './rollback-controller'

const api = vi.hoisted(() => ({
  acceptRollback: vi.fn(),
  getRollbackNotice: vi.fn(),
  lockVault: vi.fn(),
}))
vi.mock('../vault', () => api)

const notice = { recordedRevision: 9, foundRevision: 4 }

beforeEach(() => {
  vi.clearAllMocks()
})

describe('the rollback notice', () => {
  it('shows what the host found after an unlock and nothing when the host found nothing', async () => {
    api.getRollbackNotice.mockResolvedValueOnce(notice).mockResolvedValueOnce(null)
    const rollback = createRollbackController()
    await rollback.refresh()
    expect(get(rollback.state).notice).toEqual(notice)
    await rollback.refresh()
    expect(get(rollback.state).notice).toBeNull()
  })

  it('shows no notice when the host cannot answer', async () => {
    api.getRollbackNotice.mockRejectedValue(new Error('fictional failure'))
    const rollback = createRollbackController()
    await rollback.refresh()
    expect(get(rollback.state).notice).toBeNull()
  })

  it('keeps the notice and says why when keeping the vault fails', async () => {
    api.getRollbackNotice.mockResolvedValue(notice)
    api.acceptRollback.mockRejectedValue(new Error('Sesame could not record the vault revision.'))
    const rollback = createRollbackController()
    await rollback.refresh()
    await rollback.keep()
    expect(get(rollback.state).notice).toEqual(notice)
    expect(get(rollback.state).error).toBe('Sesame could not record the vault revision.')
    expect(get(rollback.state).working).toBe(false)
  })

  it('closes the notice after the person keeps the vault', async () => {
    api.getRollbackNotice.mockResolvedValue(notice)
    api.acceptRollback.mockResolvedValue(undefined)
    const rollback = createRollbackController()
    await rollback.refresh()
    await rollback.keep()
    expect(api.acceptRollback).toHaveBeenCalledTimes(1)
    expect(get(rollback.state).notice).toBeNull()
  })

  it('locks the vault and clears the notice when the person chooses to lock', async () => {
    api.getRollbackNotice.mockResolvedValue(notice)
    api.lockVault.mockResolvedValue(undefined)
    const rollback = createRollbackController()
    await rollback.refresh()
    await rollback.lock()
    expect(api.lockVault).toHaveBeenCalledTimes(1)
    expect(api.acceptRollback).not.toHaveBeenCalled()
    expect(get(rollback.state).notice).toBeNull()
  })
})

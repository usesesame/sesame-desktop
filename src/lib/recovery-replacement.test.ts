import { describe, expect, it } from 'vitest'
import { recoveryRequestPending } from './recovery-replacement'

describe('recoveryRequestPending', () => {
  it('is false without a request time', () => {
    expect(recoveryRequestPending(null)).toBe(false)
    expect(recoveryRequestPending(undefined)).toBe(false)
    expect(recoveryRequestPending({ ready: false, timeConfirmed: true })).toBe(false)
    expect(recoveryRequestPending({ requestedAt: null, ready: false, timeConfirmed: true } as never)).toBe(false)
  })

  it('is true once a request time exists', () => {
    expect(recoveryRequestPending({ requestedAt: 1_700_000_000, availableAt: 1_700_259_200, ready: false, timeConfirmed: true })).toBe(true)
  })
})

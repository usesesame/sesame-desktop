import { describe, expect, it } from 'vitest'
import { groupedFingerprint, pairingInputHasCode } from './server-pairing'

describe('server pairing helpers', () => {
  it('groups a fingerprint into blocks of eight', () => {
    expect(groupedFingerprint('0123456789abcdef'.repeat(4))).toBe('01234567 89abcdef 01234567 89abcdef 01234567 89abcdef 01234567 89abcdef')
    expect(groupedFingerprint('abc')).toBe('abc')
    expect(groupedFingerprint('')).toBe('')
  })

  it('sees a code only in a link fragment', () => {
    expect(pairingInputHasCode('https://sesame.example.test/pair#code=abc&fp=def')).toBe(true)
    expect(pairingInputHasCode('https://sesame.example.test/pair#fp=def&code=abc')).toBe(true)
    expect(pairingInputHasCode('https://sesame.example.test/pair#fp=def')).toBe(false)
    expect(pairingInputHasCode('https://sesame.example.test/pair#code=')).toBe(false)
    expect(pairingInputHasCode('https://sesame.example.test')).toBe(false)
    expect(pairingInputHasCode('https://sesame.example.test/?code=abc')).toBe(false)
    expect(pairingInputHasCode('')).toBe(false)
  })
})

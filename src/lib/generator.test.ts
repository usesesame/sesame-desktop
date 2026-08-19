import { describe, expect, it } from 'vitest'
import {
  generatorEntropy,
  makePassword,
  secureRandomIndex,
  selectedGeneratorSets,
  strengthLabel,
} from './generator'

const allOptions = { lowercase: true, uppercase: true, numbers: true, symbols: true }
const config = (overrides = {}) => ({ length: 20, options: allOptions, avoidAmbiguous: false, ...overrides })

describe('secureRandomIndex', () => {
  it('stays inside the range it was given', () => {
    for (let attempt = 0; attempt < 500; attempt += 1) {
      const value = secureRandomIndex(7)
      expect(value).toBeGreaterThanOrEqual(0)
      expect(value).toBeLessThan(7)
    }
  })

  it('reaches every value, so no character is unreachable', () => {
    const seen = new Set<number>()
    for (let attempt = 0; attempt < 2000; attempt += 1) seen.add(secureRandomIndex(10))
    expect(seen.size).toBe(10)
  })

  it('refuses a maximum it cannot draw from without bias', () => {
    expect(() => secureRandomIndex(0)).toThrow(RangeError)
    expect(() => secureRandomIndex(-1)).toThrow(RangeError)
    expect(() => secureRandomIndex(1.5)).toThrow(RangeError)
    expect(() => secureRandomIndex(2 ** 33)).toThrow(RangeError)
  })
})

describe('makePassword', () => {
  it('returns exactly the requested length', () => {
    for (const length of [12, 20, 33, 64]) {
      expect(makePassword(config({ length }))).toHaveLength(length)
    }
  })

  it('includes at least one character from every set that was asked for', () => {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const password = makePassword(config({ length: 12 }))
      expect(password).toMatch(/[a-z]/)
      expect(password).toMatch(/[A-Z]/)
      expect(password).toMatch(/[0-9]/)
      expect(password).toMatch(/[^a-zA-Z0-9]/)
    }
  })

  it('uses only characters from the sets that were asked for', () => {
    const password = makePassword(config({ length: 64, options: { lowercase: true, uppercase: false, numbers: true, symbols: false } }))
    expect(password).toMatch(/^[a-z0-9]+$/)
  })

  it('leaves out the characters that are easy to misread when asked to', () => {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      expect(makePassword(config({ length: 64, avoidAmbiguous: true }))).not.toMatch(/[Il1O0o]/)
    }
  })

  it('returns nothing when no character set is selected', () => {
    expect(makePassword(config({ options: { lowercase: false, uppercase: false, numbers: false, symbols: false } }))).toBe('')
  })

  it('does not produce the same password twice', () => {
    const seen = new Set(Array.from({ length: 50 }, () => makePassword(config())))
    expect(seen.size).toBe(50)
  })

  it('does not always place the guaranteed characters in the same positions', () => {
    const firstCharacters = new Set(Array.from({ length: 100 }, () => makePassword(config({ length: 12 }))[0]))
    expect(firstCharacters.size).toBeGreaterThan(3)
  })
})

describe('selectedGeneratorSets and entropy', () => {
  it('drops a set that was not asked for', () => {
    expect(selectedGeneratorSets({ options: { lowercase: true, uppercase: false, numbers: false, symbols: false }, avoidAmbiguous: false })).toHaveLength(1)
  })

  it('reports fewer bits for a smaller pool and a shorter password', () => {
    const full = generatorEntropy(config({ length: 20 }))
    const shorter = generatorEntropy(config({ length: 12 }))
    const narrower = generatorEntropy(config({ length: 20, options: { lowercase: true, uppercase: false, numbers: false, symbols: false } }))
    expect(shorter).toBeLessThan(full)
    expect(narrower).toBeLessThan(full)
    expect(generatorEntropy(config({ options: { lowercase: false, uppercase: false, numbers: false, symbols: false } }))).toBe(0)
  })

  it('labels strength at the documented thresholds', () => {
    expect(strengthLabel(100)).toBe('Very strong')
    expect(strengthLabel(80)).toBe('Strong')
    expect(strengthLabel(60)).toBe('Fair')
    expect(strengthLabel(59)).toBe('Weak')
  })
})

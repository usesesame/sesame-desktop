import { describe, expect, it } from 'vitest'
import { isTrivialPin, isValidPinLength, MAX_PIN_DIGITS, MIN_PIN_DIGITS, pinDigits } from './pin-rules'

describe('isTrivialPin', () => {
  it('matches the PINs the vault core refuses when one is chosen', () => {
    for (const pin of ['000000', '111111', '999999', '123456', '654321', '012345', '00000000', '1234567890', '9876543210', '555555555555']) {
      expect(isTrivialPin(pin), pin).toBe(true)
    }
  })

  it('leaves an ordinary PIN alone', () => {
    for (const pin of ['472913', '100200', '918273', '122334', '4729138', '472913850261']) {
      expect(isTrivialPin(pin), pin).toBe(false)
    }
  })
})

describe('PIN length', () => {
  it('accepts six to twelve digits, matching the vault core', () => {
    expect([MIN_PIN_DIGITS, MAX_PIN_DIGITS]).toEqual([6, 12])
    for (const pin of ['472913', '4729138', '472913850261']) expect(isValidPinLength(pin), pin).toBe(true)
    for (const pin of ['', '47291', '4729138502613', '47291a', ' 472913']) expect(isValidPinLength(pin), pin).toBe(false)
  })

  it('keeps only digits and stops at the longest PIN', () => {
    expect(pinDigits('47 29-13a')).toBe('472913')
    expect(pinDigits('4729138502613999')).toBe('472913850261')
  })
})

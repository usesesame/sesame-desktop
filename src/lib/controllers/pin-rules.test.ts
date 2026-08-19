import { describe, expect, it } from 'vitest'
import { isTrivialPin } from './settings-controller'

describe('isTrivialPin', () => {
  it('matches the PINs the vault core refuses when one is chosen', () => {
    for (const pin of ['000000', '111111', '999999', '123456', '654321', '012345']) {
      expect(isTrivialPin(pin), pin).toBe(true)
    }
  })

  it('leaves an ordinary PIN alone', () => {
    for (const pin of ['472913', '100200', '918273', '122334']) {
      expect(isTrivialPin(pin), pin).toBe(false)
    }
  })
})

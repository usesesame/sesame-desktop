import { describe, expect, test } from 'vitest'
import { DIRECTION_STAND_IN, isolatedVaultText, vaultText } from './vault-text'

describe('vault text shown in the window', () => {
  test('a direction override or isolate in a stored value becomes a visible stand-in', () => {
    expect(vaultText('Mallory ‮gnp.exe‬ Item')).toBe(`Mallory ${DIRECTION_STAND_IN}gnp.exe${DIRECTION_STAND_IN} Item`)
    for (const control of ['؜', '‎', '‏', '‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩']) {
      expect(vaultText(`north${control}wind.example`)).toBe(`north${DIRECTION_STAND_IN}wind.example`)
    }
  })

  test('ordinary text in any script and joiners inside words stay as they are', () => {
    for (const value of ['Northwind mail', 'שלום עולם', 'مرحبا', 'Café', '👩‍💻 Work', 'می‌خواهم', '']) expect(vaultText(value)).toBe(value)
    expect(vaultText(undefined)).toBe('')
  })

  test('an isolated value is wrapped so it cannot reorder the sentence around it', () => {
    expect(isolatedVaultText('Mallory ‮gnp.exe‬ Item')).toBe(`⁨Mallory ${DIRECTION_STAND_IN}gnp.exe${DIRECTION_STAND_IN} Item⁩`)
    expect(isolatedVaultText('⁩ evil')).toBe(`⁨${DIRECTION_STAND_IN} evil⁩`)
  })
})

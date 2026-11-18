import { describe, expect, test } from 'vitest'
import { DIRECTION_STAND_IN, hasHiddenCharacters, isolatedVaultText, noteText, vaultText } from './vault-text'

describe('vault text shown in the window', () => {
  test('a direction override or isolate in a stored value becomes a visible stand-in', () => {
    expect(vaultText('Mallory \u202Egnp.exe\u202C Item')).toBe(`Mallory ${DIRECTION_STAND_IN}gnp.exe${DIRECTION_STAND_IN} Item`)
    for (const control of ['\u061C', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069']) {
      expect(vaultText(`north${control}wind.example`)).toBe(`north${DIRECTION_STAND_IN}wind.example`)
    }
  })

  test('ordinary text in any script and joiners inside words stay as they are', () => {
    for (const value of ['Northwind mail', 'שלום עולם', 'مرحبا', 'Café', '👩\u200D💻 Work', 'می\u200Cخواهم', '']) expect(vaultText(value)).toBe(value)
    expect(vaultText(undefined)).toBe('')
  })

  test('an isolated value is wrapped so it cannot reorder the sentence around it', () => {
    expect(isolatedVaultText('Mallory \u202Egnp.exe\u202C Item')).toBe(`\u2068Mallory ${DIRECTION_STAND_IN}gnp.exe${DIRECTION_STAND_IN} Item\u2069`)
    expect(isolatedVaultText('\u2069 evil')).toBe(`\u2068${DIRECTION_STAND_IN} evil\u2069`)
  })
})

describe('notes and revealed secrets', () => {
  test('notes keep marks and right-to-left text and lose only overrides', () => {
    expect(noteText('שלום\u200F עולם\u2067x\u2069')).toBe('שלום\u200F עולם\u2067x\u2069')
    expect(noteText('Invoice \u202Efdp.exe\u202D')).toBe('Invoice ?fdp.exe?')
  })

  test('a secret with a hidden or direction character is detected and ordinary text is not', () => {
    for (const value of ['pass\u202Eword', 'pass\u200Bword', 'pass\u0007word', 'pass\uFEFF']) expect(hasHiddenCharacters(value)).toBe(true)
    for (const value of ['fictional-secret', 'שלום-123', 'line one\nline two\ttab', '']) expect(hasHiddenCharacters(value)).toBe(false)
  })
})

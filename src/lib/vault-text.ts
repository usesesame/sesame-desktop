const DIRECTION_CONTROLS = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/gu
const FIRST_STRONG_ISOLATE = '\u2068'
const POP_DIRECTIONAL_ISOLATE = '\u2069'

export const DIRECTION_STAND_IN = '?'

export function vaultText(value: string | null | undefined): string {
  return (value ?? '').replace(DIRECTION_CONTROLS, DIRECTION_STAND_IN)
}

export function isolatedVaultText(value: string | null | undefined): string {
  return `${FIRST_STRONG_ISOLATE}${vaultText(value)}${POP_DIRECTIONAL_ISOLATE}`
}

const DIRECTION_OVERRIDES = /[\u202D\u202E]/gu
const HIDDEN_CHARACTER = /[\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]|[^\P{Cc}\n\t]/u

export function noteText(value: string | null | undefined): string {
  return (value ?? '').replace(DIRECTION_OVERRIDES, DIRECTION_STAND_IN)
}

export function hasHiddenCharacters(value: string | null | undefined): boolean {
  return HIDDEN_CHARACTER.test(value ?? '')
}

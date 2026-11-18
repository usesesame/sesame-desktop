const DIRECTION_CONTROLS = /[؜‎‏‪-‮⁦-⁩]/gu
const FIRST_STRONG_ISOLATE = '⁨'
const POP_DIRECTIONAL_ISOLATE = '⁩'

export const DIRECTION_STAND_IN = '?'

export function vaultText(value: string | null | undefined): string {
  return (value ?? '').replace(DIRECTION_CONTROLS, DIRECTION_STAND_IN)
}

export function isolatedVaultText(value: string | null | undefined): string {
  return `${FIRST_STRONG_ISOLATE}${vaultText(value)}${POP_DIRECTIONAL_ISOLATE}`
}

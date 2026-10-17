import type { SecretView } from './types'

export function keptSecretKeys(view: SecretView<unknown>): string[] {
  return view.secretFields.filter((key) => !key.startsWith('legacy:') && !key.startsWith('field:'))
}

export function isKept(draft: { keptSecrets?: string[] }, key: string): boolean {
  return draft.keptSecrets?.includes(key) ?? false
}

export function withoutKept<T extends { keptSecrets?: string[] }>(draft: T, key: string): T {
  return { ...draft, keptSecrets: (draft.keptSecrets ?? []).filter((kept) => kept !== key) }
}

export function typedSecret<T extends { keptSecrets?: string[] }>(draft: T, key: string, value: string): boolean {
  return value.length === 0 && isKept(draft, key)
}

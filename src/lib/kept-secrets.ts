import type { CustomFieldEntry, SecretView } from './types'

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

export type DraftField = CustomFieldEntry & { keptFrom?: number }

export function draftFields(fields: CustomFieldEntry[], secretFields: string[]): DraftField[] {
  return fields.map((field, index) => (secretFields.includes(`field:${index}`) ? { ...field, value: '', keptFrom: index } : { ...field }))
}

export function isKeptField(field: DraftField): boolean {
  return field.keptFrom !== undefined && field.kind === 'secret' && !field.value
}

export function fieldsInput(rows: DraftField[]): { fields: CustomFieldEntry[]; keptSecrets: string[] } {
  const keptSecrets: string[] = []
  const fields = rows.map((row, index) => {
    const { keptFrom, ...field } = row
    if (keptFrom !== undefined && field.kind === 'secret' && !field.value) keptSecrets.push(`field:${index}<-${keptFrom}`)
    return field
  })
  return { fields, keptSecrets }
}

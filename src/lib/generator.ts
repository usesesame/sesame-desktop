import type { GeneratorOption } from './types'

export const generatorOptionKeys: GeneratorOption[] = ['lowercase', 'uppercase', 'numbers', 'symbols']

export const generatorLabels: Record<GeneratorOption, string> = {
  lowercase: 'Lowercase',
  uppercase: 'Uppercase',
  numbers: 'Numbers',
  symbols: 'Symbols',
}

const generatorCharacters: Record<GeneratorOption, string> = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?',
}

const ambiguousCharacters = new Set('Il1O0o')

export interface PasswordGeneratorConfig {
  length: number
  options: Record<GeneratorOption, boolean>
  avoidAmbiguous: boolean
}

export function selectedGeneratorSets(config: Pick<PasswordGeneratorConfig, 'options' | 'avoidAmbiguous'>): string[] {
  return generatorOptionKeys
    .filter((option) => config.options[option])
    .map((option) => {
      const characters = generatorCharacters[option]
      return config.avoidAmbiguous
        ? [...characters].filter((character) => !ambiguousCharacters.has(character)).join('')
        : characters
    })
    .filter(Boolean)
}

export function secureRandomIndex(max: number): number {
  if (!Number.isSafeInteger(max) || max <= 0 || max > 0x1_0000_0000) {
    throw new RangeError('Random index maximum must be between 1 and 2^32.')
  }
  const range = 0x1_0000_0000
  const limit = Math.floor(range / max) * max
  const value = new Uint32Array(1)
  do crypto.getRandomValues(value)
  while (value[0] >= limit)
  return value[0] % max
}

export function makePassword(config: PasswordGeneratorConfig): string {
  const sets = selectedGeneratorSets(config)
  if (!sets.length) return ''
  const pool = sets.join('')
  const characters = sets.map((set) => set[secureRandomIndex(set.length)])
  while (characters.length < config.length) characters.push(pool[secureRandomIndex(pool.length)])
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const replacement = secureRandomIndex(index + 1)
    ;[characters[index], characters[replacement]] = [characters[replacement], characters[index]]
  }
  return characters.join('')
}

export function generatorEntropy(config: PasswordGeneratorConfig): number {
  const poolSize = selectedGeneratorSets(config).reduce((total, set) => total + set.length, 0)
  return poolSize > 0 ? Math.round(config.length * Math.log2(poolSize)) : 0
}

export function strengthLabel(entropyBits: number): string {
  return entropyBits >= 100 ? 'Very strong' : entropyBits >= 80 ? 'Strong' : entropyBits >= 60 ? 'Fair' : 'Weak'
}

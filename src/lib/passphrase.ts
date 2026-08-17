import { EFF_WORDLIST } from './data/eff-wordlist'
import { secureRandomIndex } from './generator'

export interface PassphraseGeneratorConfig {
  wordCount: number
  separator: string
  capitalize: boolean
  includeNumber: boolean
}

function pickWord(): string {
  return EFF_WORDLIST[secureRandomIndex(EFF_WORDLIST.length)]
}

export function makePassphrase(config: PassphraseGeneratorConfig): string {
  if (config.wordCount <= 0) return ''
  const words = Array.from({ length: config.wordCount }, pickWord)
  const cased = config.capitalize
    ? words.map((word) => word[0].toUpperCase() + word.slice(1))
    : words
  if (config.includeNumber) {
    const index = secureRandomIndex(cased.length)
    const digit = secureRandomIndex(10)
    cased[index] = `${cased[index]}${digit}`
  }
  return cased.join(config.separator)
}

export function passphraseEntropy(config: PassphraseGeneratorConfig): number {
  if (config.wordCount <= 0) return 0
  const wordBits = config.wordCount * Math.log2(EFF_WORDLIST.length)
  const numberBits = config.includeNumber ? Math.log2(config.wordCount * 10) : 0
  return Math.round(wordBits + numberBits)
}

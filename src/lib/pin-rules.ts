export const MIN_PIN_DIGITS = 6
export const MAX_PIN_DIGITS = 12

export function pinDigits(value: string): string {
  return value.replace(/\D/g, '').slice(0, MAX_PIN_DIGITS)
}

export function isValidPinLength(pin: string): boolean {
  return new RegExp(`^\\d{${MIN_PIN_DIGITS},${MAX_PIN_DIGITS}}$`).test(pin)
}

export function isTrivialPin(pin: string): boolean {
  const digits = Array.from(pin, (character) => Number(character))
  const repeated = digits.every((digit) => digit === digits[0])
  const ascending = digits.every((digit, index) => index === 0 || digit === (digits[index - 1] + 1) % 10)
  const descending = digits.every((digit, index) => index === 0 || digits[index - 1] === (digit + 1) % 10)
  return repeated || ascending || descending
}

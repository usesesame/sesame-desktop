export function groupedFingerprint(fingerprint: string): string {
  return fingerprint.replace(/(.{8})(?=.)/g, '$1 ')
}

export function pairingInputHasCode(input: string): boolean {
  const fragment = input.split('#')[1]
  if (!fragment) return false
  return fragment.split('&').some((part) => part.startsWith('code=') && part.length > 'code='.length)
}

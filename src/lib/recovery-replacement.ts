import type { RecoveryReplacementStatus } from './types'

export function recoveryRequestPending(status: RecoveryReplacementStatus | null | undefined): boolean {
  return typeof status?.requestedAt === 'number'
}

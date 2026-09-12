import type { BackupCompatibility } from './types'

export interface BackupFormatCopy {
  canRestore: boolean
  label: string
  detail: string
  nextAction: string
}

export function describeBackupCompatibility(
  compatibility: BackupCompatibility,
  formatVersion: number,
): BackupFormatCopy {
  switch (compatibility) {
    case 'current':
      return {
        canRestore: true,
        label: `Sesame format ${formatVersion}`,
        detail: 'This backup is in the current Sesame format.',
        nextAction: '',
      }
    case 'upgrade':
      return {
        canRestore: true,
        label: `Older Sesame format ${formatVersion}`,
        detail: 'Sesame upgrades a copy of this older format when it restores. The selected file is not changed.',
        nextAction: 'Keep the original file until the restore finishes.',
      }
    case 'newer':
      return {
        canRestore: false,
        label: `Sesame format ${formatVersion}`,
        detail: 'This backup was written by a newer version of Sesame.',
        nextAction: 'Update Sesame, then choose this file again.',
      }
    case 'unsupported':
      return {
        canRestore: false,
        label: `Sesame format ${formatVersion}`,
        detail: 'This backup is older than the formats this version of Sesame can open.',
        nextAction: 'Keep this file and contact support.',
      }
  }
}

export interface OlderBackup {
  restoredRevision: number
  currentRevision: number
}

const OLDER_BACKUP = /^olderBackup:(\d+):(\d+)$/

export function parseOlderBackup(message: string): OlderBackup | null {
  const match = OLDER_BACKUP.exec(message)
  if (!match) return null
  return { restoredRevision: Number(match[1]), currentRevision: Number(match[2]) }
}

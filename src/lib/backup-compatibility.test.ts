import { describe, expect, it } from 'vitest'
import { describeBackupCompatibility } from './backup-compatibility'

describe('describeBackupCompatibility', () => {
  it('names a current backup and allows a restore', () => {
    const copy = describeBackupCompatibility('current', 10)
    expect(copy.canRestore).toBe(true)
    expect(copy.label).toBe('Sesame format 10')
    expect(copy.detail).toMatch(/current Sesame format/)
    expect(copy.detail).not.toMatch(/broken|damaged|corrupt/i)
  })

  it('explains that an older format is upgraded on a copy', () => {
    const copy = describeBackupCompatibility('upgrade', 8)
    expect(copy.canRestore).toBe(true)
    expect(copy.label).toBe('Older Sesame format 8')
    expect(copy.detail).toMatch(/upgrades a copy/)
    expect(copy.detail).toMatch(/selected file is not changed/)
    expect(copy.nextAction).toMatch(/Keep the original file/)
    expect(copy.detail).not.toMatch(/broken|damaged|corrupt/i)
  })

  it('sends a newer format to the update action without offering a restore', () => {
    const copy = describeBackupCompatibility('newer', 11)
    expect(copy.canRestore).toBe(false)
    expect(copy.label).toBe('Sesame format 11')
    expect(copy.detail).toMatch(/newer version of Sesame/)
    expect(copy.nextAction).toBe('Update Sesame, then choose this file again.')
  })

  it('gives an unsupported format one next action without calling it damaged', () => {
    const copy = describeBackupCompatibility('unsupported', 1)
    expect(copy.canRestore).toBe(false)
    expect(copy.nextAction).toBe('Keep this file and contact support.')
    expect(copy.detail).not.toMatch(/broken|damaged|corrupt/i)
  })
})

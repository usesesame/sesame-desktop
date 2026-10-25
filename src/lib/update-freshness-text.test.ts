import { describe, expect, it } from 'vitest'
import { describeFreshness, noUpdateNotice } from './update-freshness-text'

const at = 1_800_000_000

describe('update freshness wording', () => {
  it('says nothing extra when the build has no freshness source or the check is confirmed', () => {
    expect(describeFreshness({ available: false })).toBe('')
    expect(describeFreshness({ available: false, freshness: { state: 'confirmed', at } })).toBe('')
  })

  it('says that a newer release exists when the update information is frozen', () => {
    const text = describeFreshness({ available: false, freshness: { state: 'newer_exists', version: '0.4.9' } })
    expect(text).toContain('Sesame 0.4.9')
    expect(text).toContain('releases page')
  })

  it('says it could not confirm updates, with the date when there is one', () => {
    expect(describeFreshness({ available: false, freshness: { state: 'unconfirmed' } })).toBe('Sesame could not confirm that no update is waiting. Check your connection or the releases page.')
    expect(describeFreshness({ available: false, freshness: { state: 'unconfirmed', at } })).toMatch(/^Sesame has not confirmed that no update is waiting since .+\. Check your connection or the releases page\.$/)
  })

  it('never claims the latest version unless the check is confirmed or has no freshness source', () => {
    expect(noUpdateNotice({ available: false })).toEqual({ title: 'No update available', message: 'You are running the latest version of Sesame.' })
    expect(noUpdateNotice({ available: false, freshness: { state: 'confirmed', at } }).message).toBe('You are running the latest version of Sesame.')
    const stale = noUpdateNotice({ available: false, freshness: { state: 'unconfirmed' } })
    expect(stale.title).toBe('Could not confirm updates')
    expect(stale.message).not.toContain('latest version')
    const frozen = noUpdateNotice({ available: false, freshness: { state: 'newer_exists', version: '0.4.9' } })
    expect(frozen.title).toBe('A newer Sesame exists')
    expect(frozen.message).not.toContain('latest version')
  })

  it('does not describe freshness while an update is ready to install', () => {
    expect(describeFreshness({ available: true, version: '0.4.5', freshness: { state: 'unconfirmed' } })).toBe('')
  })
})

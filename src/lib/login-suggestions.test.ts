import { describe, expect, it } from 'vitest'
import type { VaultEntrySummary } from './types'
import { folderToSuggest, hostOf, loginsOnSite, nameFromUrl, sameSite, tagsToSuggest } from './login-suggestions'

function entry(overrides: Partial<VaultEntrySummary> & { id: string }): VaultEntrySummary {
  return {
    title: overrides.id,
    site: 'example.test',
    initials: 'E',
    folder: '',
    favourite: false,
    passwordScore: 4,
    passwordIssues: [],
    securityLevel: 'good',
    issueKinds: [],
    tags: [],
    updatedAt: 1,
    ...overrides,
  }
}

describe('reading a website the way a person types it', () => {
  it('finds the host in an address typed with or without a scheme, path or port', () => {
    expect(hostOf('github.com')).toBe('github.com')
    expect(hostOf('  https://www.GitHub.com/login?next=1#top ')).toBe('github.com')
    expect(hostOf('http://localhost:5173/app')).toBe('localhost')
    expect(hostOf('example.test:8443')).toBe('example.test')
  })

  it('never returns a password or user name that was typed into the address', () => {
    expect(hostOf('https://fictional-user:fictional-secret@example.test/path')).toBe('example.test')
  })

  it('returns nothing for text that is not a host yet', () => {
    expect(hostOf('')).toBe('')
    expect(hostOf('gith')).toBe('')
    expect(hostOf('https://')).toBe('')
    expect(hostOf('two words.com')).toBe('')
    expect(hostOf('No website saved')).toBe('')
  })

  it('treats a subdomain and its parent as one site, and nothing else', () => {
    expect(sameSite('login.example.test', 'example.test')).toBe(true)
    expect(sameSite('example.test', 'login.example.test')).toBe(true)
    expect(sameSite('example.test', 'example.test')).toBe(true)
    expect(sameSite('example.test', 'notexample.test')).toBe(false)
    expect(sameSite('a.github.io', 'b.github.io')).toBe(false)
    expect(sameSite('', '')).toBe(false)
  })
})

describe('a name taken from the website', () => {
  it('uses the main part of the host', () => {
    expect(nameFromUrl('github.com')).toBe('Github')
    expect(nameFromUrl('https://mail.google.com/inbox')).toBe('Google')
    expect(nameFromUrl('www.my-bank.example')).toBe('My bank')
  })

  it('handles the common two part endings', () => {
    expect(nameFromUrl('bbc.co.uk')).toBe('Bbc')
    expect(nameFromUrl('news.example.com.au')).toBe('Example')
  })

  it('gives nothing for an address with no usable name', () => {
    expect(nameFromUrl('')).toBe('')
    expect(nameFromUrl('localhost')).toBe('')
    expect(nameFromUrl('192.0.2.10')).toBe('')
    expect(nameFromUrl('gith')).toBe('')
  })
})

describe('what the vault already holds for a site', () => {
  const entries = [
    entry({ id: 'older', site: 'example.test', folderId: 'work', folder: 'Work', tags: ['mail', 'work'], updatedAt: 5 }),
    entry({ id: 'newer', site: 'login.example.test', folderId: 'work', folder: 'Work', tags: ['work'], updatedAt: 9 }),
    entry({ id: 'other-folder', site: 'example.test', folderId: 'home', folder: 'Home', updatedAt: 2 }),
    entry({ id: 'elsewhere', site: 'unrelated.test', folderId: 'fun', folder: 'Fun', tags: ['games', 'games-2'], updatedAt: 3 }),
    entry({ id: 'unsaved', site: 'No website saved', updatedAt: 4 }),
  ]

  it('lists logins on the same site, most recently changed first, and not the one being edited', () => {
    expect(loginsOnSite('https://example.test', entries).map((item) => item.id)).toEqual(['newer', 'older', 'other-folder'])
    expect(loginsOnSite('example.test', entries, 'newer').map((item) => item.id)).toEqual(['older', 'other-folder'])
  })

  it('lists nothing until the address is a real host', () => {
    expect(loginsOnSite('exa', entries)).toEqual([])
    expect(loginsOnSite('', entries)).toEqual([])
  })

  it('prefers a recently used login over one that merely changed later', () => {
    const used = [entry({ id: 'used', site: 'example.test', lastUsedAt: 100, updatedAt: 1 }), entry({ id: 'edited', site: 'example.test', updatedAt: 50 })]
    expect(loginsOnSite('example.test', used).map((item) => item.id)).toEqual(['used', 'edited'])
  })

  it('suggests the folder most of the matching logins use, unless it is already chosen', () => {
    const matches = loginsOnSite('example.test', entries)
    expect(folderToSuggest(matches, undefined)).toEqual({ id: 'work', name: 'Work' })
    expect(folderToSuggest(matches, 'work')).toBeNull()
    expect(folderToSuggest([], undefined)).toBeNull()
    expect(folderToSuggest([entry({ id: 'plain', site: 'example.test' })], undefined)).toBeNull()
  })

  it('breaks a folder tie in favour of the most recent login', () => {
    const tied = [entry({ id: 'a', folderId: 'one', folder: 'One', updatedAt: 1 }), entry({ id: 'b', folderId: 'two', folder: 'Two', updatedAt: 2 })]
    expect(folderToSuggest(tied, undefined)).toEqual({ id: 'two', name: 'Two' })
  })

  it('suggests tags from the same site first and then the most used ones, never one already applied', () => {
    const matches = loginsOnSite('example.test', entries)
    expect(tagsToSuggest(matches, entries, [], 5)).toEqual(['work', 'mail', 'games', 'games-2'])
    expect(tagsToSuggest(matches, entries, ['Work'], 5)).toEqual(['mail', 'games', 'games-2'])
    expect(tagsToSuggest([], entries, [], 2)).toEqual(['work', 'mail'])
  })
})

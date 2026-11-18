import { afterEach, expect, test, vi } from 'vitest'
import { get } from 'svelte/store'
import { clearEmailAliases, emailAliases, loadEmailAliases, removeEmailAliases, saveEmailAliases } from './email-aliases'
import type { EmailAliasStatus } from './types'

const vault = vi.hoisted(() => ({
  getEmailAliasSettings: vi.fn(),
  saveEmailAliasSettings: vi.fn(),
  removeEmailAliasSettings: vi.fn(),
}))

vi.mock('./vault', () => vault)

const configured: EmailAliasStatus = { service: 'addy', domain: 'anonaddy.me', nameSite: false }
const off: EmailAliasStatus = { nameSite: false }

function pending<T>() {
  let resolve: (value: T) => void = () => {}
  let reject: (error: Error) => void = () => {}
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

afterEach(() => {
  clearEmailAliases()
  vi.clearAllMocks()
})

test('a read that started before a removal cannot bring the token back', async () => {
  const read = pending<EmailAliasStatus>()
  vault.getEmailAliasSettings.mockReturnValueOnce(read.promise)
  vault.removeEmailAliasSettings.mockResolvedValue(off)
  emailAliases.set(configured)

  const loading = loadEmailAliases()
  await removeEmailAliases()
  read.resolve(configured)
  await loading

  expect(get(emailAliases)).toEqual(off)
})

test('a read that started during a removal cannot bring the token back', async () => {
  const removal = pending<EmailAliasStatus>()
  const read = pending<EmailAliasStatus>()
  vault.removeEmailAliasSettings.mockReturnValueOnce(removal.promise)
  vault.getEmailAliasSettings.mockReturnValueOnce(read.promise)
  emailAliases.set(configured)

  const removing = removeEmailAliases()
  const loading = loadEmailAliases()
  removal.resolve(off)
  await removing
  read.resolve(configured)
  await loading

  expect(get(emailAliases)).toEqual(off)
})

test('an earlier save that answers last does not replace a later one', async () => {
  const first = pending<EmailAliasStatus>()
  const later: EmailAliasStatus = { service: 'simpleLogin', nameSite: true }
  vault.saveEmailAliasSettings.mockReturnValueOnce(first.promise).mockResolvedValueOnce(later)

  const saving = saveEmailAliases({ service: 'addy', token: 'fictional-token', domain: 'anonaddy.me', nameSite: false })
  await saveEmailAliases({ service: 'simpleLogin', token: 'fictional-token', nameSite: true })
  first.resolve(configured)
  await saving

  expect(get(emailAliases)).toEqual(later)
})

test('a later change that fails reads the vault again instead of keeping a passed over answer', async () => {
  const first = pending<EmailAliasStatus>()
  vault.saveEmailAliasSettings.mockReturnValueOnce(first.promise)
  vault.removeEmailAliasSettings.mockRejectedValueOnce(new Error('Unlock your vault first.'))
  vault.getEmailAliasSettings.mockResolvedValue(configured)
  emailAliases.set(off)

  const saving = saveEmailAliases({ service: 'addy', token: 'fictional-token', domain: 'anonaddy.me', nameSite: false })
  await expect(removeEmailAliases()).rejects.toThrow('Unlock your vault first.')
  first.resolve(configured)
  await saving

  await vi.waitFor(() => expect(get(emailAliases)).toEqual(configured))
  expect(vault.getEmailAliasSettings).toHaveBeenCalledOnce()
})

/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import { get } from 'svelte/store'
import { clearEmailAliases, emailAliases } from '../email-aliases'
import EmailAliasesSetting from './EmailAliasesSetting.svelte'

const vault = vi.hoisted(() => ({
  getEmailAliasSettings: vi.fn(),
  saveEmailAliasSettings: vi.fn(),
  removeEmailAliasSettings: vi.fn(),
}))

vi.mock('../vault', () => vault)

afterEach(() => {
  cleanup()
  clearEmailAliases()
  vi.clearAllMocks()
})

test('aliases start off and the token form opens from the switch', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  render(EmailAliasesSetting)
  const toggle = screen.getByRole('switch', { name: 'Email aliases' })
  expect(toggle.getAttribute('aria-checked')).toBe('false')
  expect(screen.queryByLabelText('API token')).toBeNull()

  await fireEvent.click(toggle)

  expect(screen.getByLabelText('API token').getAttribute('type')).toBe('password')
  expect((screen.getByLabelText('Alias domain') as HTMLInputElement).value).toBe('anonaddy.me')
  expect(screen.queryByRole('switch', { name: 'Name the site in alias descriptions' })).toBeNull()
})

test('saving sends the pasted token once and the field is emptied straight away', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  vault.saveEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  render(EmailAliasesSetting)
  await fireEvent.click(screen.getByRole('switch', { name: 'Email aliases' }))
  await fireEvent.input(screen.getByLabelText('API token'), { target: { value: 'fictional-alias-token' } })

  await fireEvent.click(screen.getByRole('button', { name: 'Save token' }))

  expect(vault.saveEmailAliasSettings).toHaveBeenCalledWith({ service: 'addy', token: 'fictional-alias-token', domain: 'anonaddy.me', nameSite: false })
  await waitFor(() => expect(screen.queryByLabelText('API token')).toBeNull())
  expect(screen.getByText('addy.io')).toBeTruthy()
  expect(document.body.textContent).not.toContain('fictional-alias-token')
  expect([...document.querySelectorAll('input')].map((input) => input.value)).not.toContain('fictional-alias-token')
  expect(JSON.stringify(get(emailAliases))).not.toContain('fictional-alias-token')
})

test('naming the site is a separate switch that never resends a token', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ service: 'simpleLogin', nameSite: false })
  vault.saveEmailAliasSettings.mockResolvedValue({ service: 'simpleLogin', nameSite: true })
  render(EmailAliasesSetting)

  await fireEvent.click(await screen.findByRole('switch', { name: 'Name the site in alias descriptions' }))

  expect(vault.saveEmailAliasSettings).toHaveBeenCalledWith({ service: 'simpleLogin', domain: undefined, nameSite: true })
  await waitFor(() => expect(screen.getByRole('switch', { name: 'Name the site in alias descriptions' }).getAttribute('aria-checked')).toBe('true'))
})

test('turning aliases off forgets the token', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: true })
  vault.removeEmailAliasSettings.mockResolvedValue({ nameSite: false })
  render(EmailAliasesSetting)
  const toggle = await screen.findByRole('switch', { name: 'Email aliases' })
  await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('true'))

  await fireEvent.click(toggle)

  expect(vault.removeEmailAliasSettings).toHaveBeenCalledOnce()
  await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('false'))
})

test('a refused token shows the backend message inside the form', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  vault.saveEmailAliasSettings.mockRejectedValue(new Error('That does not look like an API token. Copy it again from your alias service.'))
  render(EmailAliasesSetting)
  await fireEvent.click(screen.getByRole('switch', { name: 'Email aliases' }))
  await fireEvent.input(screen.getByLabelText('API token'), { target: { value: 'bad token' } })

  await fireEvent.click(screen.getByRole('button', { name: 'Save token' }))

  expect((await screen.findByRole('alert')).textContent).toBe('That does not look like an API token. Copy it again from your alias service.')
  expect((screen.getByLabelText('API token') as HTMLInputElement).value).toBe('')
})

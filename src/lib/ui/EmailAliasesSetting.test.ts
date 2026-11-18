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

async function readySwitch() {
  const toggle = screen.getByRole('switch', { name: 'Email aliases' }) as HTMLButtonElement
  await waitFor(() => expect(toggle.disabled).toBe(false))
  return toggle
}

test('aliases start off and the token form opens from the switch', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  render(EmailAliasesSetting)
  const toggle = await readySwitch()
  expect(toggle.getAttribute('aria-checked')).toBe('false')
  expect(screen.queryByLabelText('API token')).toBeNull()

  await fireEvent.click(toggle)

  expect(toggle.getAttribute('aria-checked')).toBe('false')
  expect(toggle.classList.contains('active')).toBe(false)
  expect(toggle.getAttribute('aria-controls')).toBe('alias-form')
  expect(document.getElementById('alias-form')).toBeTruthy()
  const tokenField = screen.getByLabelText('API token')
  await waitFor(() => expect(document.activeElement).toBe(tokenField))
  expect(tokenField.getAttribute('aria-describedby')).toBe('alias-token-help')
  expect(document.getElementById('alias-token-help')?.textContent).toBe('Create an API key in your addy.io account under Settings, then API Keys.')
  expect(screen.getByLabelText('API token').getAttribute('type')).toBe('password')
  expect((screen.getByLabelText('Alias domain') as HTMLInputElement).value).toBe('anonaddy.me')
  expect(screen.queryByRole('switch', { name: 'Name the site in alias descriptions' })).toBeNull()

  await fireEvent.click(toggle)

  expect(screen.queryByLabelText('API token')).toBeNull()
  expect(toggle.getAttribute('aria-checked')).toBe('false')
  expect(toggle.hasAttribute('aria-controls')).toBe(false)
})

test('saving sends the pasted token once and the field is emptied straight away', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  vault.saveEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  render(EmailAliasesSetting)
  await fireEvent.click(await readySwitch())
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

test('turning aliases off removes the token and says where copies remain', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: true })
  vault.removeEmailAliasSettings.mockResolvedValue({ nameSite: false })
  render(EmailAliasesSetting)
  const toggle = await screen.findByRole('switch', { name: 'Email aliases' })
  await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('true'))
  expect(document.body.textContent).toContain('Turning this off removes the token from your vault, but older backups and synced versions keep it, so revoke it at addy.io to stop it working.')
  expect(document.body.textContent).not.toMatch(/forget|delete/i)

  await fireEvent.click(toggle)

  expect(vault.removeEmailAliasSettings).toHaveBeenCalledOnce()
  await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('false'))
})

test('a refused token shows the backend message inside the form', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  vault.saveEmailAliasSettings.mockRejectedValue(new Error('That does not look like an API token. Copy it again from your alias service.'))
  render(EmailAliasesSetting)
  await fireEvent.click(await readySwitch())
  await fireEvent.input(screen.getByLabelText('API token'), { target: { value: 'bad token' } })

  await fireEvent.click(screen.getByRole('button', { name: 'Save token' }))

  expect((await screen.findByRole('alert')).textContent).toBe('That does not look like an API token. Copy it again from your alias service.')
  const tokenField = screen.getByLabelText('API token') as HTMLInputElement
  expect(tokenField.value).toBe('')
  expect(tokenField.getAttribute('aria-describedby')).toBe('alias-token-help alias-form-error')
  expect(tokenField.getAttribute('aria-invalid')).toBe('true')
  expect(screen.getByRole('switch', { name: 'Email aliases' }).getAttribute('aria-checked')).toBe('false')
})

test('a setting that could not be read is not shown as off and can be read again', async () => {
  vault.getEmailAliasSettings.mockRejectedValueOnce(new Error('Unlock your vault first.'))
  render(EmailAliasesSetting)
  const toggle = screen.getByRole('switch', { name: 'Email aliases' }) as HTMLButtonElement

  expect((await screen.findByRole('alert')).textContent).toBe('Unlock your vault first.')
  expect(toggle.disabled).toBe(true)
  await fireEvent.click(toggle)
  expect(screen.queryByLabelText('API token')).toBeNull()

  vault.getEmailAliasSettings.mockResolvedValueOnce({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  await fireEvent.click(screen.getByRole('button', { name: 'Try again' }))

  await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('true'))
  expect(toggle.disabled).toBe(false)
  expect(screen.queryByRole('alert')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
})

test('closing the token form puts focus back on the control that opened it', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  render(EmailAliasesSetting)
  const toggle = await readySwitch()
  await fireEvent.click(toggle)
  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(document.activeElement).toBe(toggle))

  cleanup()
  clearEmailAliases()
  vault.getEmailAliasSettings.mockResolvedValue({ service: 'addy', domain: 'anonaddy.me', nameSite: false })
  render(EmailAliasesSetting)
  await fireEvent.click(await screen.findByRole('button', { name: 'Replace token' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Replace token' })))
})

test('a refused alias domain marks the domain field and not the token field', async () => {
  vault.getEmailAliasSettings.mockResolvedValue({ nameSite: false })
  vault.saveEmailAliasSettings.mockRejectedValue(new Error('Enter the domain your aliases use, such as anonaddy.me.'))
  render(EmailAliasesSetting)
  const toggle = await readySwitch()
  await fireEvent.click(toggle)
  await fireEvent.input(screen.getByLabelText('API token'), { target: { value: 'fictional-alias-token' } })
  await fireEvent.input(screen.getByLabelText('Alias domain'), { target: { value: 'not a domain' } })

  await fireEvent.click(screen.getByRole('button', { name: 'Save token' }))

  expect((await screen.findByRole('alert')).textContent).toBe('Enter the domain your aliases use, such as anonaddy.me.')
  const domainField = screen.getByLabelText('Alias domain')
  expect(domainField.getAttribute('aria-invalid')).toBe('true')
  expect(domainField.getAttribute('aria-describedby')).toBe('alias-form-error')
  const tokenField = screen.getByLabelText('API token')
  expect(tokenField.hasAttribute('aria-invalid')).toBe(false)
  expect(tokenField.getAttribute('aria-describedby')).toBe('alias-token-help')
})

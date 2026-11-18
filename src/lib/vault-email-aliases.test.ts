import { expect, test } from 'vitest'
import { createEmailAlias, getEmailAliasSettings, previewMode, removeEmailAliasSettings, saveEmailAliasSettings } from './vault'

test('the preview falls back to the default addy.io domain when the field is left blank', async () => {
  expect(previewMode).toBe(true)
  await saveEmailAliasSettings({ service: 'addy', token: 'fictional-token', domain: '   ', nameSite: false })
  expect((await getEmailAliasSettings()).domain).toBeUndefined()
  expect(await createEmailAlias()).toBe('quiet.harbor.42@anonaddy.me')

  await saveEmailAliasSettings({ service: 'addy', token: 'fictional-token', domain: ' Mail.Fictional.Example ', nameSite: false })
  expect(await createEmailAlias()).toBe('quiet.harbor.42@mail.fictional.example')
  await removeEmailAliasSettings()
})

test('the preview refuses an addy.io domain the app would refuse', async () => {
  await saveEmailAliasSettings({ service: 'addy', token: 'fictional-token', domain: 'mail.fictional.example.', nameSite: false })
  expect((await getEmailAliasSettings()).domain).toBe('mail.fictional.example')
  for (const bad of ['not a domain', 'localhost', '-fictional.example', 'fictional..example', 'fictional.example:443', '1.2.3.4']) {
    await expect(saveEmailAliasSettings({ service: 'addy', token: 'fictional-token', domain: bad, nameSite: false }), bad).rejects.toThrow('Enter the domain your aliases use, such as anonaddy.me.')
  }
  expect(await createEmailAlias()).toBe('quiet.harbor.42@mail.fictional.example')
  await removeEmailAliasSettings()
})

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

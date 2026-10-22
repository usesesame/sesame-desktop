import { describe, expect, it } from 'vitest'
import { itemDetail, type ItemRecordView } from './item-fields'

const base = { id: 'fictional-id', tags: [], favourite: false, createdAt: 1, updatedAt: 2, revision: 1, legacyFields: [] }

describe('itemDetail', () => {
  it('lists a card secret as a concealed field with no value', () => {
    const detail = itemDetail('card', {
      ...base,
      title: 'Fictional card',
      cardholderName: 'Casey Example',
      number: '',
      expiryMonth: '04',
      expiryYear: '2031',
      securityCode: '',
      brand: 'Fictional brand',
      notes: '',
      secretFields: ['number', 'securityCode'],
    } as ItemRecordView)

    const secrets = detail.fields.filter((field) => field.secret)
    expect(secrets.map((field) => [field.label, field.secretKey, field.value])).toEqual([
      ['Card number', 'number', ''],
      ['Security code', 'securityCode', ''],
    ])
    expect(detail.fields.find((field) => field.label === 'Expiry')?.value).toBe('04/2031')
  })

  it('omits a secret the item does not hold', () => {
    const detail = itemDetail('card', {
      ...base,
      title: 'Fictional card',
      cardholderName: '',
      number: '',
      expiryMonth: '',
      expiryYear: '',
      securityCode: '',
      brand: '',
      notes: '',
      secretFields: ['number'],
    } as ItemRecordView)

    expect(detail.fields.map((field) => field.label)).toEqual(['Card number'])
  })

  it('names each secret kind by the key the host uses', () => {
    const wifi = itemDetail('wifi_network', { ...base, title: 'Fictional network', ssid: 'Fictional', password: '', securityType: 'WPA2', notes: '', secretFields: ['password'] } as ItemRecordView)
    const ssh = itemDetail('ssh_key', { ...base, title: 'Fictional key', keyType: 'ed25519', privateKey: '', publicKey: 'ssh-ed25519 FICTIONAL', passphrase: '', notes: '', secretFields: ['privateKey', 'passphrase'] } as ItemRecordView)
    const license = itemDetail('software_license', { ...base, title: 'Fictional licence', productName: 'Fictional app', licenseKey: '', purchasedFrom: '', purchaseDate: '', notes: '', secretFields: ['licenseKey'] } as ItemRecordView)
    const document = itemDetail('document', { ...base, title: 'Fictional document', documentType: 'Passport', documentNumber: '', issuingAuthority: '', issueDate: '', expiryDate: '', notes: '', attachments: [], secretFields: ['documentNumber'] } as ItemRecordView)

    expect(wifi.fields.filter((field) => field.secret).map((field) => field.secretKey)).toEqual(['password'])
    expect(ssh.fields.filter((field) => field.secret).map((field) => [field.secretKey, field.multiline])).toEqual([['privateKey', true], ['passphrase', false]])
    expect(ssh.fields.find((field) => field.label === 'Public key')?.value).toBe('ssh-ed25519 FICTIONAL')
    expect(license.fields.filter((field) => field.secret).map((field) => field.secretKey)).toEqual(['licenseKey'])
    expect(document.fields.filter((field) => field.secret).map((field) => field.secretKey)).toEqual(['documentNumber'])
  })

  it('keys custom record secrets by position and keeps plain fields visible', () => {
    const detail = itemDetail('custom_record', {
      ...base,
      title: 'Fictional record',
      notes: '',
      fields: [
        { label: 'Visible', value: 'fictional visible', kind: 'text' },
        { label: 'Hidden', value: '', kind: 'secret' },
      ],
      secretFields: ['field:1'],
    } as ItemRecordView)

    expect(detail.fields.map((field) => [field.label, field.secretKey ?? null, field.value])).toEqual([
      ['Visible', null, 'fictional visible'],
      ['Hidden', 'field:1', ''],
    ])
  })

  it('shows an open note body in the detail and a locked note as a concealed field', () => {
    const open = itemDetail('secure_note', { ...base, title: 'Fictional note', content: 'fictional open body', tags: [], secretFields: [] } as ItemRecordView)
    expect(open.locked).toBe(false)
    expect(open.fields.map((field) => [field.label, field.secret, field.value])).toEqual([['Content', false, 'fictional open body']])

    const locked = itemDetail('secure_note', { ...base, title: 'Fictional note', content: '', locked: true, tags: [], secretFields: ['content'] } as ItemRecordView)
    expect(locked.locked).toBe(true)
    expect(locked.fields.map((field) => [field.label, field.secret, field.secretKey, field.value])).toEqual([['Content', true, 'content', '']])
  })

  it('keeps a locked note marked as locked even when its body is empty', () => {
    const locked = itemDetail('secure_note', { ...base, title: 'Fictional note', content: '', locked: true, tags: [], secretFields: [] } as ItemRecordView)
    expect(locked.locked).toBe(true)
    expect(locked.fields).toEqual([])
  })
})
